"""MCP server (stdio) for Claude Code and Codex. Tool results never contain secret values.

No tool blocks for long: Codex ends an MCP call after 60 s by default, so waiting is secret_wait,
called again while the owner is still typing.

A client that declares URL elicitation gets the page opened for the owner: on 2025-11-25 sessions as
an elicitation/create request, on 2026-07-28 (Claude Code 2.1.287+) as an InputRequiredResult that the
client answers and retries. Everyone else gets the link as text for the agent to pass on."""

from __future__ import annotations

import asyncio
import json
import logging
import time

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.context import Context
from mcp.server.request_state import RequestStateSecurity
from mcp.types import ElicitRequest, ElicitRequestURLParams, InputRequiredResult, ToolAnnotations
from mcp_types.version import MODERN_PROTOCOL_VERSIONS

from .client import allowed
from .policy import socket_path
from .protocol import BrokerError, call

MAX_WAIT_SECONDS = 50
log = logging.getLogger(__name__)

server = MCPServer(
    "secret-broker",
    instructions=(
        "Credentials (API keys, tokens, passwords) go through secret-broker; values never appear in tool "
        "results, and you never ask for one in the chat, print one or write one to a file. "
        "1) secret_list shows which secrets are stored and which commands each may go with. "
        "2) If the one you need isn't stored, call secret_request. The owner doesn't see tool results: unless "
        "it says the page is already open, write the link it returns into your reply, word for word, then "
        "call secret_wait until it says stored. "
        "3) Run the command in your shell as `secret run NAME -- command args`; the command must read NAME "
        "from its environment ($NAME on your command line expands to nothing). "
        "If secret run exits 77 because there is no policy entry, show the owner the snippet from the "
        "message and stop; you can't change the policy. If the shell can't reach the broker, the message "
        "says which sandbox setting the owner needs."
    ),
    # request_state carries the link between the dialog and the retry; a day outlives any link.
    request_state_security=RequestStateSecurity.ephemeral(ttl=86400),
)

# Clients that approve read-only tools without asking (Codex "writes" mode) can let list and wait through.
READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=False)

# name -> token of a URL elicitation still open in this session, closed with elicitation/complete.
_open_elicitations: dict[str, str] = {}


def _supports_url_elicitation(ctx: Context) -> bool:
    caps = ctx.client_capabilities
    return bool(caps and caps.elicitation and caps.elicitation.url is not None)


def _after_dialog(name: str, action: str | None, link: str) -> str:
    if action == "accept":
        return f"The owner opened the page for {name}. Call secret_wait with name {name} until it says stored."
    if action == "decline":
        return f"The owner declined to open the page for {name}. Don't ask again unless they say so."
    return link  # dismissed, or a client that answered nothing: the agent passes the link on


@server.tool(
    annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False),
    structured_output=False,
)
async def secret_request(name: str, why: str, ctx: Context) -> str | InputRequiredResult:
    """Ask the owner for a secret's value through a one-time page that writes it straight to the
    store. Returns the link to show the owner (or opens it for them when the client can); then call
    secret_wait. The value itself is never returned."""
    if ctx.request_state is not None:  # the retry after the client showed the page to the owner
        answer = (ctx.input_responses or {}).get("open_page")
        return _after_dialog(name, getattr(answer, "action", None), json.loads(ctx.request_state)["link"])
    try:
        reply = await asyncio.to_thread(call, socket_path(), {"op": "request", "name": name, "why": why})
    except BrokerError as exc:
        return f"secret broker error: {exc}"
    url, token, ttl = reply["url"], reply["token"], reply["ttl_minutes"]
    link = (
        f"The owner can't see this tool result. Put this link in your reply, exactly as written, and say it is "
        f"for {name} ({why}); it works once and expires in {ttl} min:\n{url}\n"
        f"Then call secret_wait with name {name}."
    )
    if not reply.get("policy", True):
        link += (
            f"\nNote: {name} has no policy entry, so `secret run` will refuse it until the owner adds "
            f'[secrets.{name}] allow = [["<program>"]] to {reply.get("policy_file") or "the policy file"} '
            "and runs: sudo systemctl reload secret-broker"
        )
    if not _supports_url_elicitation(ctx):
        return link
    message = (
        f"The agent needs the secret {name} ({why}). Open the page and enter the value; it is "
        f"written straight to the secret store and never passes through the model."
    )
    if ctx.protocol_version in MODERN_PROTOCOL_VERSIONS:  # no back-channel: ask through the result
        return InputRequiredResult(
            input_requests={"open_page": ElicitRequest(params=ElicitRequestURLParams(message=message, url=url))},
            request_state=json.dumps({"link": link}),
        )
    try:
        result = await ctx.elicit_url(message=message, url=url, elicitation_id=token)
    except Exception as exc:  # noqa: BLE001 - a client that refuses the request still gets the link as text
        log.warning("couldn't open the page through the client (%s); returning the link", exc)
        return link
    if result.action == "accept":
        _open_elicitations[name] = token  # 2025-11-25 only: closed with elicitation/complete
    return _after_dialog(name, result.action, link)


@server.tool(annotations=READ_ONLY, structured_output=False)
async def secret_wait(name: str, ctx: Context, timeout_seconds: int = 45) -> str:
    """Wait until the value asked for with secret_request is saved, for at most timeout_seconds
    (capped at 50). Says stored, expired, or still waiting; call it again while it's waiting."""
    sock = socket_path()
    deadline = time.time() + max(1, min(timeout_seconds, MAX_WAIT_SECONDS))
    while True:
        try:
            status = await asyncio.to_thread(call, sock, {"op": "status", "name": name})
        except BrokerError as exc:
            return f"secret broker error: {exc}"
        state = status.get("state")
        if state == "stored":
            token = _open_elicitations.pop(name, None)
            if token:
                try:
                    await ctx.session.send_elicit_complete(token)
                except Exception:  # noqa: BLE001 - the notification is optional
                    pass
            return f"Stored {name}. Use it with: secret run {name} -- <command>"
        if state == "expired":
            return f"The link for {name} expired before a value was entered. Ask again with secret_request if it's still needed."
        if state == "unknown":
            return f"There is no open request for {name}. Ask for it with secret_request first."
        if time.time() >= deadline:
            return f"Still waiting for the owner to enter {name}. Call secret_wait again."
        await asyncio.sleep(2)


@server.tool(annotations=READ_ONLY, structured_output=False)
async def secret_list() -> str:
    """List secret names known to the broker, whether each is stored, and the commands each may go
    with. Never values."""
    try:
        reply = await asyncio.to_thread(call, socket_path(), {"op": "list"})
    except BrokerError as exc:
        return f"secret broker error: {exc}"
    if not reply["names"]:
        return "no secrets stored and no policy entries"
    return "\n".join(
        f"{n['name']}: {'stored' if n['stored'] else 'not stored'}; allowed: {allowed(n)}"
        for n in reply["names"]
    )


def run() -> None:
    server.run(transport="stdio")
