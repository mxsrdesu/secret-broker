"""One JSON object per line over the broker's unix socket."""

from __future__ import annotations

import errno
import json
import socket

MAX_LINE = 1 << 20


class BrokerError(RuntimeError):
    """code: "denied" (policy said no), "missing" (value not stored yet) or "error"."""

    def __init__(self, message: str, code: str = "error"):
        super().__init__(message)
        self.code = code


def _sandboxed(socket_path: str) -> str:
    return (
        f"the agent's sandbox blocks the connection to the secret broker at {socket_path}. "
        "Let `secret` run outside it: in Claude Code add \"secret *\" to sandbox.excludedCommands; "
        "in Codex set sandbox_workspace_write.network_access = true"
    )


def connect(socket_path: str, timeout: float = 30.0) -> socket.socket:
    # A sandbox's seccomp filter answers EPERM (Claude Code already on socket(), Codex on connect());
    # file permissions answer EACCES.
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except PermissionError as exc:
        raise BrokerError(_sandboxed(socket_path)) from exc
    sock.settimeout(timeout)
    try:
        sock.connect(socket_path)
    except PermissionError as exc:
        sock.close()
        if exc.errno == errno.EPERM:
            raise BrokerError(_sandboxed(socket_path)) from exc
        raise BrokerError(
            f"no access to the secret broker at {socket_path}. Your user must be in the secret-broker group, "
            "and a session started before you were added doesn't have it yet: log out and back in, "
            "or run `newgrp secret-broker` in this terminal"
        ) from exc
    except FileNotFoundError as exc:
        sock.close()
        raise BrokerError(
            f"the secret broker isn't running on this machine (no {socket_path}). Check: systemctl status secret-broker"
        ) from exc
    except OSError as exc:
        sock.close()
        raise BrokerError(f"secret broker is not reachable at {socket_path}: {exc.strerror or exc}") from exc
    return sock


def read_reply(sock: socket.socket) -> dict:
    """Read one reply line; raise BrokerError unless it says ok."""
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
        if len(buf) > MAX_LINE:
            raise BrokerError("broker reply too large")
    if not buf:
        raise BrokerError("broker closed the connection without a reply")
    reply = json.loads(buf.split(b"\n", 1)[0])
    if not reply.get("ok"):
        raise BrokerError(reply.get("error", "unknown broker error"), reply.get("code", "error"))
    return reply


def call(socket_path: str, request: dict, timeout: float = 30.0) -> dict:
    with connect(socket_path, timeout) as sock:
        sock.sendall(json.dumps(request).encode() + b"\n")
        return read_reply(sock)
