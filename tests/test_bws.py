"""bws backend against a fake `bws` CLI that keeps secrets in a JSON file."""

import json
import os
import sys
import stat
import textwrap
from pathlib import Path

import pytest

from secret_broker.backends.bws import BwsBackend

FAKE_BWS = r'''#!/usr/bin/env python3
import json, os, sys, uuid
store = os.path.join(os.environ["HOME"], "fake-store.json")  # HOME = broker state dir
# The real bws refuses to start when BWS_CONFIG_FILE names a file that does not exist.
if not os.path.exists(os.environ["BWS_CONFIG_FILE"]):
    sys.stderr.write("Error: \n\nCaused by:\n    Config file doesn't exist\n"); sys.exit(1)
if os.environ.get("BWS_ACCESS_TOKEN") != "good-token":
    sys.stderr.write("Error: Access token invalid\n"); sys.exit(1)
db = json.load(open(store)) if os.path.exists(store) else {"projects": [{"id": "p1", "name": "personal"}], "secrets": []}
args = sys.argv[1:]
def dump(x): print(json.dumps(x))
if args[:2] == ["project", "list"]:
    dump(db["projects"])
elif args[:2] == ["secret", "list"]:
    proj = [a for a in args[2:] if not a.startswith("-") and a != "json"]
    dump([s for s in db["secrets"] if not proj or s["projectId"] == proj[0]])
elif args[:2] == ["secret", "create"]:
    key, value, project = args[2], args[3], args[4]
    db["secrets"].append({"id": str(uuid.uuid4()), "key": key, "value": value, "projectId": project}); dump(db["secrets"][-1])
elif args[:2] == ["secret", "edit"]:
    value = args[args.index("--value") + 1]; sid = args[-1]
    for s in db["secrets"]:
        if s["id"] == sid: s["value"] = value; dump(s)
else:
    sys.stderr.write("unsupported: " + " ".join(args) + "\n"); sys.exit(2)
json.dump(db, open(store, "w"))
'''


@pytest.fixture
def fake_bws(tmp_path: Path, monkeypatch):
    exe = tmp_path / "bws"
    # No /usr/bin/env inside the Nix build sandbox: point the shebang at the running interpreter.
    exe.write_text(FAKE_BWS.replace("#!/usr/bin/env python3", f"#!{sys.executable}", 1))
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    return str(exe)


def test_unconfigured_then_bootstrap_then_roundtrip(fake_bws, tmp_path: Path):
    backend = BwsBackend(token_file=str(tmp_path / "state" / "token"), bws=fake_bws)
    assert not backend.configured()
    with pytest.raises(RuntimeError, match="not configured"):
        backend.names()
    backend.install_token("good-token\n")
    assert backend.configured()
    assert oct((tmp_path / "state" / "token").stat().st_mode & 0o777) == "0o600"
    assert backend.names() == []
    backend.set("GH_TOKEN", "v1")           # single project → auto-detected
    assert backend.get("GH_TOKEN") == "v1"
    backend.set("GH_TOKEN", "v2")           # edit path
    assert backend.get("GH_TOKEN") == "v2"
    assert backend.names() == ["GH_TOKEN"]
    assert backend.get("NOPE") is None


def test_bad_token_error_has_no_value(fake_bws, tmp_path: Path):
    backend = BwsBackend(token_file=str(tmp_path / "token"), bws=fake_bws)
    backend.install_token("wrong")
    with pytest.raises(RuntimeError) as exc:
        backend.set("X", "topsecret")
    assert "topsecret" not in str(exc.value)


def test_config_file_created_minimal_and_kept(fake_bws, tmp_path: Path):
    backend = BwsBackend(token_file=str(tmp_path / "token"), bws=fake_bws)
    backend.install_token("good-token")
    assert backend.names() == []
    config = tmp_path / "bws-state" / "config"
    assert config.read_text() == "[profiles]\n"
    assert oct(config.stat().st_mode & 0o777) == "0o600"
    # An operator's own file (e.g. written by `bws config server-base`) is left alone without server_url.
    config.write_text('[profiles.default]\nserver_base = "https://vault.bitwarden.eu"\n')
    backend.names()
    assert "bitwarden.eu" in config.read_text()


def test_server_url_owns_the_config_file(fake_bws, tmp_path: Path):
    backend = BwsBackend(token_file=str(tmp_path / "token"), bws=fake_bws, server_url="https://vault.bitwarden.eu/")
    backend.install_token("good-token")
    config = tmp_path / "bws-state" / "config"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("[profiles]\n")
    assert backend.names() == []
    assert config.read_text() == '[profiles.default]\nserver_base = "https://vault.bitwarden.eu"\n'


def test_first_list_reaches_bws_right_after_boot(fake_bws, tmp_path: Path, monkeypatch):
    """time.monotonic() starts near zero at boot; a broker started then must not serve an empty cache."""
    import secret_broker.backends.bws as bws_module

    monkeypatch.setattr(bws_module.time, "monotonic", lambda: 5.0)
    backend = BwsBackend(token_file=str(tmp_path / "token"), bws=fake_bws)
    backend.install_token("good-token")
    backend.set("GH_TOKEN", "v1")
    fresh = BwsBackend(token_file=str(tmp_path / "token"), bws=fake_bws)
    assert fresh.names() == ["GH_TOKEN"]
