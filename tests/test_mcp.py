"""The MCP tools against a real daemon: a client without URL elicitation gets the link as text, one
with it gets the page opened; neither ever sees the value."""

import anyio
import pytest
from mcp import Client
from mcp import types

from secret_broker import mcp_server
from test_run import VALUE, enter_value, start_daemon


@pytest.fixture
def broker(tmp_path, monkeypatch):
    proc, info = start_daemon(tmp_path)
    monkeypatch.setenv("SECRET_BROKER_SOCKET", str(info["sock"]))
    yield info
    proc.terminate()
    proc.wait(timeout=10)


def text(result) -> str:
    return "".join(c.text for c in result.content if isinstance(c, types.TextContent))


def link_in(answer: str) -> str:
    return next(word for word in answer.split() if word.startswith("http"))


def test_link_as_text_then_wait(broker):
    async def scenario():
        async with Client(mcp_server.server) as client:
            answer = text(await client.call_tool("secret_request", {"name": "TEST_TOKEN", "why": "test"}))
            assert "secret_wait" in answer and "no policy" not in answer
            url = link_in(answer)
            waiting = text(await client.call_tool("secret_wait", {"name": "TEST_TOKEN", "timeout_seconds": 1}))
            assert waiting.startswith("Still waiting")
            await anyio.to_thread.run_sync(enter_value, url, VALUE)
            done = text(await client.call_tool("secret_wait", {"name": "TEST_TOKEN"}))
            listed = text(await client.call_tool("secret_list", {}))
            return answer + waiting + done + listed, done, listed

    everything, done, listed = anyio.run(scenario)
    assert done.startswith("Stored TEST_TOKEN") and "secret run TEST_TOKEN" in done
    assert "TEST_TOKEN: stored; allowed: show-env; true; git; gh" in listed
    assert VALUE not in everything


def test_only_request_changes_anything():
    async def scenario():
        async with Client(mcp_server.server) as client:
            return {t.name: t.annotations.read_only_hint for t in (await client.list_tools()).tools}

    assert anyio.run(scenario) == {"secret_request": False, "secret_wait": True, "secret_list": True}


def test_missing_policy_is_named(broker):
    async def scenario():
        async with Client(mcp_server.server) as client:
            return text(await client.call_tool("secret_request", {"name": "NEW_TOKEN", "why": "test"}))

    answer = anyio.run(scenario)
    assert "[secrets.NEW_TOKEN]" in answer and "systemctl reload secret-broker" in answer


@pytest.mark.parametrize("action", ["accept", "decline", "cancel"])
@pytest.mark.parametrize("mode", ["legacy", "auto"])
def test_url_elicitation(broker, mode, action):
    """legacy: a 2025-11-25 session, the server sends elicitation/create. auto: 2026-07-28, as Claude Code
    speaks it; the tool returns InputRequiredResult and the client retries with the owner's answer."""
    asked, completed = [], []

    async def on_elicit(_context, params):
        asked.append(params)
        return types.ElicitResult(action=action)

    async def on_message(message):
        if isinstance(message, types.ElicitCompleteNotification):
            completed.append(message.params.elicitation_id)

    async def scenario():
        async with Client(mcp_server.server, mode=mode, elicitation_callback=on_elicit, message_handler=on_message) as client:
            answer = text(await client.call_tool("secret_request", {"name": "TEST_TOKEN", "why": "test"}))
            if action != "accept":
                return answer, ""
            await anyio.to_thread.run_sync(enter_value, asked[0].url, VALUE)
            return answer, text(await client.call_tool("secret_wait", {"name": "TEST_TOKEN"}))

    answer, done = anyio.run(scenario)
    [params] = asked
    assert params.mode == "url" and "/r/" in params.url and VALUE not in params.message
    if action == "accept":
        assert "opened the page" in answer and done.startswith("Stored TEST_TOKEN")
        assert completed == ([params.elicitation_id] if mode == "legacy" else [])
    elif action == "decline":
        assert "declined" in answer and "http" not in answer
    else:  # dismissed: the agent still gets the link to pass on
        assert link_in(answer) == params.url and "Put this link in your reply" in answer
