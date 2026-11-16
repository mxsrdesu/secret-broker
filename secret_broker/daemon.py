"""secret-brokerd: unix-socket API for the `secret` CLI plus a tiny web page where the owner
types a value. The value goes from the browser straight into the backend; the agent only ever
sees secret names, URLs with one-time tokens and redacted command output."""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import json
import logging
import os
import pwd
import secrets as pysecrets
import select
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import tomllib
import urllib.parse
from dataclasses import dataclass, field

from . import page
from .backends import check_backend, make_backend
from .backends.base import Backend, NotConfigured
from .policy import Config, allowed_commands, check, config_path, load_config, socket_path, _validate_name
from .protocol import MAX_LINE, BrokerError, call
from .redact import Redactor

log = logging.getLogger("secret-broker")

# Client variables that would make the child load code or config of the caller's choosing.
SCRUBBED_ENV = frozenset({
    "GIT_SSH", "GIT_SSH_COMMAND", "GIT_EXEC_PATH", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT",
    "GIT_ASKPASS", "SSH_ASKPASS", "GIT_PROXY_COMMAND", "GIT_EDITOR", "GIT_PAGER", "GIT_SEQUENCE_EDITOR",
    "GIT_EXTERNAL_DIFF", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_TEMPLATE_DIR",
    "PAGER", "EDITOR", "VISUAL", "BROWSER", "GH_PAGER", "GH_EDITOR", "GH_BROWSER",
})
SCRUBBED_ENV_PREFIXES = ("LD_", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")
FORWARDED_SIGNALS = frozenset({signal.SIGINT, signal.SIGTERM, signal.SIGHUP})

PR_SET_NO_NEW_PRIVS, PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL = 38, 47, 4
_libc = ctypes.CDLL(None, use_errno=True)
_libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
_libc.prctl.restype = ctypes.c_int


def _deny(error: str) -> dict:
    return {"ok": False, "code": "denied", "error": error}


def _fail(error: str) -> dict:
    return {"ok": False, "code": "error", "error": error}


@dataclass
class PendingRequest:
    token: str
    name: str
    why: str
    uid: int
    created: float
    expires: float
    state: str = "pending"  # pending | storing | stored | expired
    nonce: str = field(default_factory=lambda: pysecrets.token_urlsafe(16))
    stored_at: float = 0.0


class Broker:
    def __init__(self, config: Config, backend: Backend):
        # Replaced as a whole on reload; each request works on the object it read first.
        self.config = config
        self.backend = backend
        self.pending: dict[str, PendingRequest] = {}
        # Connection threads read pending while others add (request) and remove (_sweep) entries.
        self.pending_lock = threading.Lock()

    def reload(self) -> None:
        """SIGHUP: reread the policy. What the running sockets and the store were built from stays as it is."""
        old = self.config
        try:
            new = load_config(old.source)
            check_backend(new.backend, new.backend_options)
        except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
            log.error("reload failed, the current policy stays: %s: %s", old.source, exc)
            return
        fixed = [key for key in ("socket", "http_bind", "backend", "backend_options") if getattr(new, key) != getattr(old, key)]
        for key in fixed:
            setattr(new, key, getattr(old, key))
        if fixed:
            log.warning("reload: %s changed; restart secret-broker to apply that", ", ".join(fixed))
        for warning in new.warnings:
            log.warning("%s: %s", new.source, warning)
        self.config = new
        log.info("policy reloaded from %s: %d secret(s)", new.source, len(new.secrets))

    # ---- housekeeping -------------------------------------------------------------------
    def _sweep(self) -> None:
        now = time.time()
        with self.pending_lock:
            for token, req in list(self.pending.items()):
                if req.state == "pending" and now > req.expires:
                    req.state = "expired"
                    log.info("request expired name=%s uid=%s", req.name, req.uid)
                if req.state != "pending" and now > req.expires + 3600:
                    self.pending.pop(token, None)

    # ---- unix socket API -------------------------------------------------------------------
    def _gate(self, req: dict, uid: int, config: Config) -> dict | None:
        bootstrap = getattr(self.backend, "BOOTSTRAP_NAME", None)
        if bootstrap and req.get("op") in ("request", "add") and str(req.get("name", "")) == bootstrap:
            if uid != 0:
                log.warning("denied uid=%s op=%s name=%s reason=bootstrap-needs-root", uid, req.get("op"), bootstrap)
                return _deny(f"{bootstrap} is the secret store's own credential; install it as root with: sudo secret add {bootstrap}")
            return None  # root may install it even when uid 0 is not in allowed_uids
        if config.allowed_uids is not None and uid not in config.allowed_uids:
            log.warning("denied uid=%s op=%s reason=uid-not-allowed", uid, req.get("op"))
            return _deny(f"uid {uid} may not use the secret broker")
        return None

    def handle(self, req: dict, uid: int) -> dict:
        config = self.config
        self._sweep()
        denied = self._gate(req, uid, config)
        if denied:
            return denied
        op = req.get("op")
        if op == "list":
            note = ""
            try:
                stored = set(self.backend.names())
            except Exception as exc:  # noqa: BLE001 - e.g. backend not configured yet
                stored = set()
                note = str(exc)
            names = sorted(stored | set(config.secrets))
            return {
                "ok": True,
                "note": note,
                "names": [
                    {
                        "name": n,
                        "stored": n in stored,
                        "policy": n in config.secrets,
                        "allow": [list(p) for p in config.secrets[n].allow] if n in config.secrets else [],
                    }
                    for n in names
                ],
            }
        if op == "request":
            name = str(req.get("name", ""))
            _validate_name(name)
            why = str(req.get("why", ""))[:500]
            now = time.time()
            token = pysecrets.token_urlsafe(32)
            pending = PendingRequest(
                token=token, name=name, why=why, uid=uid, created=now,
                expires=now + 60 * config.request_ttl_minutes,
            )
            with self.pending_lock:
                self.pending[token] = pending
            log.info("request name=%s uid=%s why=%r", name, uid, why[:120])
            return {
                "ok": True,
                "token": token,
                "url": f"{config.public_base_url.rstrip('/')}/r/{token}",
                "expires": pending.expires,
                "ttl_minutes": config.request_ttl_minutes,
                # The store's own credential needs no entry: no command ever gets it.
                "policy": name in config.secrets or name == getattr(self.backend, "BOOTSTRAP_NAME", None),
                "allow": allowed_commands(config.secrets[name]) if name in config.secrets else "",
                "policy_file": config.source,
            }
        if op == "add":
            # The owner typing a value at a terminal: the same write the page does, without a link.
            name = str(req.get("name", ""))
            _validate_name(name)
            value = req.get("value")
            if not isinstance(value, str) or not value.strip():
                return _fail("enter a value")
            try:
                self._store(name, value.strip())
            except NotConfigured as exc:
                log.error("add failed name=%s uid=%s: %s", name, uid, exc)
                return _fail(str(exc))
            except Exception as exc:  # noqa: BLE001 - reported to the owner, the value is never logged
                log.error("add failed name=%s uid=%s: %s", name, uid, exc)
                return _fail(f"the secret store didn't accept {name}; see journalctl -u secret-broker")
            log.info("add name=%s uid=%s", name, uid)
            # An agent waiting on a link for this name (`secret wait`) sees the value typed here too.
            now = time.time()
            with self.pending_lock:
                for waiting in self.pending.values():
                    if waiting.name == name and waiting.state == "pending":
                        waiting.stored_at, waiting.state = now, "stored"
            return {"ok": True}
        if op == "status":
            if "token" in req:
                pending = self.pending.get(str(req.get("token", "")))
            else:
                pending = self._status_by_name(str(req.get("name", "")), uid)
            if pending is None:
                return {"ok": True, "state": "unknown"}
            return {"ok": True, "state": pending.state, "name": pending.name, "expires": pending.expires}
        return {"ok": False, "error": f"unknown op {op!r}"}

    def _status_by_name(self, name: str, uid: int) -> PendingRequest | None:
        """For `secret wait NAME`, which has no token: the caller's newest request for NAME, unless the
        owner used an earlier link of theirs after that one was made (the agent asked twice, or two
        agents of the same user did)."""
        with self.pending_lock:
            mine = [p for p in self.pending.values() if p.uid == uid and p.name == name]
        if not mine:
            return None
        newest = max(mine, key=lambda p: p.created)
        used = [p for p in mine if p.state == "stored" and p.stored_at >= newest.created]
        return used[0] if used else newest

    def _run(self, conn: socket.socket, req: dict, uid: int, fds: list[int], rest: bytes) -> dict:
        """Run argv as the peer with the values in its environment; stdio and cwd are the peer's own fds."""
        config = self.config
        denied = self._gate(req, uid, config)
        if denied:
            return denied
        if config.allowed_uids is None:
            return _deny("run needs allowed_uids in policy.toml")
        if uid == 0:
            return _deny("the broker never runs commands as root")
        if len(fds) != 4:
            return _fail("run needs stdin, stdout, stderr and the current directory passed with the request; use `secret run`")
        stdin_fd, out_fd, err_fd, cwd_fd = fds
        if not stat.S_ISDIR(os.fstat(cwd_fd).st_mode):
            return _fail("the fourth descriptor must be the current directory")
        names = [str(n) for n in req.get("names", [])]
        argv = [str(a) for a in req.get("argv", [])]
        client_env = req.get("env", {})
        if not isinstance(client_env, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in client_env.items()):
            return _fail("env must map names to strings")
        try:
            user = pwd.getpwuid(uid)
        except KeyError:
            return _fail(f"uid {uid} has no passwd entry")
        trusted = [d.replace("{user}", user.pw_name) for d in config.trusted_path]
        # check() looks at the basename only, which is the same before and after resolution.
        decision = check(config, names, argv)
        program = _resolve(argv[0], trusted) if decision.allowed else None
        reason = decision.reason
        if decision.allowed and program is None:
            where = "is not in a trusted directory" if "/" in argv[0] else "is not found in the trusted path"
            reason = f"'{argv[0]}' {where} ({':'.join(trusted)})"
        try:
            cwd = os.readlink(f"/proc/self/fd/{cwd_fd}")
        except OSError:
            cwd = "-"
        log.info(
            "run names=%s uid=%s argv0=%s cwd=%s decision=%s",
            ",".join(names), uid, program or (argv[0] if argv else "-"), cwd,
            "allow" if program else f"deny({reason})",
        )
        if not program:
            return _deny(reason)
        values: dict[str, str] = {}
        for name in names:
            value = self.backend.get(name)
            if value is None:
                return {
                    "ok": False,
                    "code": "missing",
                    "error": f"{name} is not stored yet; ask the owner with: secret request {name} --why '<reason>'",
                }
            values[name] = value
        env = {k: v for k, v in client_env.items() if k not in SCRUBBED_ENV and not k.startswith(SCRUBBED_ENV_PREFIXES)}
        env["PATH"] = ":".join(trusted)
        env.update(values)
        # The child becomes the peer. With the daemon's own uid (tests) there is nothing to switch.
        as_peer = {} if uid == os.getuid() else {
            "user": uid, "group": user.pw_gid, "extra_groups": os.getgrouplist(user.pw_name, user.pw_gid),
        }
        conn.settimeout(None)
        try:
            proc = subprocess.Popen(
                argv, executable=program, env=env, stdin=stdin_fd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                preexec_fn=_child_setup(cwd_fd), **as_peer,
            )
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            log.warning("run start failed uid=%s argv0=%s error=%s", uid, program, exc)
            return _fail(f"could not start {argv[0]}: {exc}")
        code = self._pump(conn, proc, values, out_fd, err_fd, rest)
        log.info("run done names=%s uid=%s argv0=%s exit=%s", ",".join(names), uid, program, code)
        return {"ok": True, "exit": code}

    def _pump(self, conn: socket.socket, proc: subprocess.Popen, values: dict[str, str], out_fd: int, err_fd: int, buf: bytes) -> int:
        """Redact the child's output into the peer's fds; deliver {"signal": N} lines from the peer."""
        sel = selectors.DefaultSelector()
        streams = {}
        for pipe, target in ((proc.stdout, out_fd), (proc.stderr, err_fd)):
            streams[pipe.fileno()] = (Redactor(values), target, pipe)
            sel.register(pipe, selectors.EVENT_READ)
        sel.register(conn, selectors.EVENT_READ)
        buf = _deliver(proc, buf)
        while streams or proc.poll() is None:
            if not sel.get_map():
                break
            events = sel.select(timeout=0.15)
            if not events:
                for red, target, _pipe in streams.values():
                    if red.pending:
                        _emit(target, red.flush())
                continue
            for key, _mask in events:
                if key.fileobj is conn:
                    try:
                        data = conn.recv(4096)
                    except OSError:
                        data = b""
                    if data:
                        buf = _deliver(proc, buf + data)
                    else:
                        sel.unregister(conn)
                        log.info("client gone, terminating pid=%s", proc.pid)
                        _signal(proc, signal.SIGTERM)
                    continue
                red, target, pipe = streams[key.fd]
                data = os.read(key.fd, 65536)
                # A peer that stopped reading gets what a pipeline gives: the child's next write fails.
                if not _emit(target, red.feed(data) if data else red.flush(final=True)) or not data:
                    sel.unregister(pipe)
                    pipe.close()
                    del streams[key.fd]
        sel.close()
        rc = proc.wait()
        return 128 - rc if rc < 0 else rc

    def _conn(self, conn: socket.socket) -> None:
        uid = -1
        fds: list[int] = []
        with conn:
            try:
                creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
                _pid, uid, _gid = struct.unpack("3i", creds)
                conn.settimeout(10)
                line, rest = _read_request(conn, fds)
                request = json.loads(line or b"{}")
                if request.get("op") == "run":
                    reply = self._run(conn, request, uid, fds, rest)
                else:
                    reply = self.handle(request, uid)
            except Exception as exc:  # noqa: BLE001 - every failure becomes a reply
                log.warning("bad request uid=%s error=%s", uid, exc)
                reply = _fail(f"bad request: {exc}")
            finally:
                for fd in fds:
                    os.close(fd)
            try:
                conn.sendall(json.dumps(reply).encode() + b"\n")
            except OSError:
                pass

    async def serve_unix(self) -> None:
        path = socket_path(self.config)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(path)
            os.chmod(path, 0o660)
            server.listen(64)
            server.setblocking(False)
            log.info("listening on %s (backend=%s, http=%s)", path, self.config.backend, self.config.http_bind)
            self.unix_ready.set()
            loop = asyncio.get_running_loop()
            while True:
                conn, _addr = await loop.sock_accept(server)
                conn.setblocking(True)
                # A thread per connection: `run` keeps its connection for as long as the command runs.
                threading.Thread(target=self._conn, args=(conn,), daemon=True).start()

    def _store(self, name: str, value: str) -> None:
        """Write a value. The backend's own credential (bws machine token) is installed through the
        same page, so the owner never has to ssh in and paste it by hand."""
        bootstrap = getattr(self.backend, "BOOTSTRAP_NAME", None)
        if bootstrap and name == bootstrap:
            self.backend.install_token(value)
            return
        self.backend.set(name, value)

    # ---- web page ---------------------------------------------------------------------------
    def _page(self, token: str, error: str = "") -> tuple[int, str]:
        self._sweep()
        pending = self.pending.get(token)
        if pending is None or pending.state == "expired":
            return 404, page.expired(socket.gethostname(), pending.name if pending else "")
        if pending.state == "stored":
            return 200, page.already_stored(pending.name, socket.gethostname())
        seconds_left = int(pending.expires - time.time())
        return 200, page.request_form(pending.name, pending.why, pending.nonce, seconds_left, socket.gethostname(), error)

    async def http_app(self, scope, receive, send):  # minimal ASGI app, no framework needed
        if scope["type"] != "http":
            return
        path = scope.get("path", "")
        method = scope.get("method", "GET")
        if path == "/healthz":
            await _respond(send, 200, "ok", "text/plain")
            return
        if not path.startswith("/r/"):
            await _respond(send, 404, "not found", "text/plain")
            return
        token = path[3:].strip("/")
        if method == "GET":
            status, body_html = self._page(token)
            await _respond(send, status, body_html)
            return
        if method != "POST":
            await _respond(send, 405, "method not allowed", "text/plain")
            return
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if len(body) > 65536:
                await _respond(send, 413, "too large", "text/plain")
                return
            if not message.get("more_body"):
                break
        form = urllib.parse.parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
        pending = self.pending.get(token)
        if pending is None or pending.state != "pending" or time.time() > pending.expires:
            status, body_html = self._page(token)
            await _respond(send, status, body_html)
            return
        if form.get("check", [""])[0] != pending.nonce:
            status, body_html = self._page(token, error="stale")
            await _respond(send, 400, body_html)
            return
        value = form.get("value", [""])[0]
        if not value.strip():
            status, body_html = self._page(token, error="empty")
            await _respond(send, 400, body_html)
            return
        # Set before the first await, so a second POST of the same form sees it and stores nothing.
        pending.state = "storing"
        try:
            await asyncio.to_thread(self._store, pending.name, value.strip())
        except Exception as exc:  # noqa: BLE001
            log.error("store failed name=%s error=%s", pending.name, exc)
            pending.state = "pending"
            status, body_html = self._page(token, error="setup" if isinstance(exc, NotConfigured) else "store")
            await _respond(send, 500, body_html)
            return
        pending.stored_at = time.time()
        pending.state = "stored"
        log.info("stored name=%s via web uid=%s", pending.name, pending.uid)
        await _respond(send, 200, page.stored(pending.name, socket.gethostname()))

    async def serve_http(self) -> None:
        import uvicorn

        async def app(scope, receive, send):  # plain ASGI3 callable (uvicorn mis-detects bound methods)
            await self.http_app(scope, receive, send)

        config = uvicorn.Config(
            app, host=self.config.http_host, port=self.config.http_port, interface="asgi3",
            log_level="warning", access_log=False, server_header=False, date_header=False,
        )
        self.http_server = uvicorn.Server(config)
        await self.http_server.serve()

    async def run(self) -> None:
        asyncio.get_running_loop().add_signal_handler(signal.SIGHUP, self.reload)
        if _early_reload.is_set():  # SIGHUP while starting: the file may have changed after it was read
            self.reload()
        self.unix_ready = asyncio.Event()
        self.http_server = None
        unix_task = asyncio.create_task(self.serve_unix())
        http_task = asyncio.create_task(self.serve_http())
        tasks = {unix_task, http_task}
        # systemd (Type=notify) holds `start` and any `reload` until both sockets accept connections.
        while not (self.unix_ready.is_set() and self.http_server and self.http_server.started):
            done, _ = await asyncio.wait(tasks, timeout=0.05, return_when=asyncio.FIRST_COMPLETED)
            if done:
                break
        else:
            _sd_notify("READY=1")
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            exc = task.exception()
            if exc:
                raise exc


def _read_request(conn: socket.socket, fds: list[int]) -> tuple[bytes, bytes]:
    """First line of the connection, plus whatever followed it. Passed fds are appended to `fds`."""
    data, received, flags, _addr = socket.recv_fds(conn, 65536, 4, socket.MSG_CMSG_CLOEXEC)
    fds.extend(received)
    if flags & socket.MSG_CTRUNC:
        raise ValueError("too many file descriptors")
    buf = data
    while data and b"\n" not in buf:
        data = conn.recv(65536)
        buf += data
        if len(buf) > MAX_LINE:
            raise ValueError("request too large")
    line, _sep, rest = buf.partition(b"\n")
    return line, rest


def _resolve(argv0: str, trusted: list[str]) -> str | None:
    """Absolute path of argv0 in a trusted directory, or None. The caller's PATH plays no part."""
    dirs = [os.path.normpath(d) for d in trusted]
    if "/" in argv0:
        candidates = [os.path.normpath(argv0)] if os.path.normpath(os.path.dirname(argv0)) in dirs else []
    else:
        candidates = [os.path.join(d, argv0) for d in dirs]
    for path in candidates:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def _child_setup(cwd_fd: int):
    def setup() -> None:
        # CPython calls this after setgroups/setregid/setreuid and before exec, so the directory is
        # entered with the peer's rights (cwd= would chdir as the daemon, before the switch).
        os.fchdir(cwd_fd)
        # The daemon's ambient CAP_SETUID/CAP_SETGID would otherwise survive the exec.
        if _libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_CAP_AMBIENT_CLEAR_ALL) failed")
        # Inheritable caps are left set; with no_new_privs no file capability or setuid bit can use them.
        if _libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS) failed")

    return setup


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        try:
            view = view[os.write(fd, view):]
        except BlockingIOError:  # the peer's file may be non-blocking
            select.select([], [fd], [])


def _emit(fd: int, data: bytes) -> bool:
    try:
        _write_all(fd, data)
        return True
    except OSError:
        return False


def _signal(proc: subprocess.Popen, sig: int) -> None:
    try:
        proc.send_signal(sig)
    except (ProcessLookupError, PermissionError) as exc:
        log.warning("signal %s to pid=%s failed: %s", sig, proc.pid, exc)


def _deliver(proc: subprocess.Popen, buf: bytes) -> bytes:
    while b"\n" in buf:
        line, buf = buf.split(b"\n", 1)
        try:
            sig = int(json.loads(line)["signal"])
        except (ValueError, KeyError, TypeError):
            continue
        if sig in FORWARDED_SIGNALS:
            _signal(proc, sig)
    return buf if len(buf) <= MAX_LINE else b""


async def _respond(send, status: int, body: str, content_type: str = "text/html; charset=utf-8") -> None:
    payload = body.encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", content_type.encode()),
            (b"content-length", str(len(payload)).encode()),
            (b"cache-control", b"no-store"),
            (b"referrer-policy", b"no-referrer"),
            (b"x-content-type-options", b"nosniff"),
        ],
    })
    await send({"type": "http.response.body", "body": payload})


def bootstrap(config: Config) -> int:
    """Print a one-time link for the secret store's own credential. The daemon only accepts it from root."""
    if config.backend != "bws":
        print(f"secret-brokerd: the {config.backend} backend has no credential to bootstrap", file=sys.stderr)
        return 1
    from .backends.bws import BwsBackend

    name = BwsBackend.BOOTSTRAP_NAME
    try:
        reply = call(socket_path(config), {"op": "request", "name": name, "why": "bootstrap: the secret store's own credential"})
    except BrokerError as exc:
        print(f"secret-brokerd: {exc}", file=sys.stderr)
        return 1
    print(f"Open this link and enter {name} (expires in {reply['ttl_minutes']} min):")
    print(reply["url"])
    return 0


_early_reload = threading.Event()


def _sd_notify(message: str) -> None:
    """Tell systemd (Type=notify) about the service; nothing when not started by it."""
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return
    if address.startswith("@"):
        address = "\0" + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC) as sock:
            sock.connect(address)
            sock.sendall(message.encode())
    except OSError as exc:
        log.warning("could not notify systemd: %s", exc)


def _load(path: str | None) -> Config:
    """The policy, or one line naming what is wrong with it and exit 1: no traceback, no restart loop noise."""
    path = path or config_path()
    try:
        config = load_config(path)
        check_backend(config.backend, config.backend_options)
    except FileNotFoundError:
        sys.exit(f"secret-brokerd: no policy file at {path}; start from examples/policy.toml in the secret-broker repo")
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        sys.exit(f"secret-brokerd: {path}: {exc}")
    return config


def main(argv: list[str] | None = None) -> None:
    # Until the event loop takes SIGHUP over, a reload must not kill the broker (the default action).
    signal.signal(signal.SIGHUP, lambda _signum, _frame: _early_reload.set())
    parser = argparse.ArgumentParser(prog="secret-brokerd")
    parser.add_argument("--config", default=None, help="policy.toml (default: $SECRET_BROKER_CONFIG or /etc/secret-broker/policy.toml)")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("bootstrap", help="as root: print a one-time link for the secret store's own credential")
    p = sub.add_parser("check", help="check policy.toml and say what is wrong")
    p.add_argument("--reload", type=int, metavar="PID", help="if it's fine, tell the broker PID to reload it (systemctl reload does this)")
    args = parser.parse_args(argv)
    config = _load(args.config)
    if args.cmd == "bootstrap":
        sys.exit(bootstrap(config))
    if args.cmd == "check":
        for warning in config.warnings:
            print(f"warning: {config.source}: {warning}", file=sys.stderr)
        print(f"{config.source}: ok, backend {config.backend}, {len(config.secrets)} secret(s) with a policy")
        if args.reload:
            os.kill(args.reload, signal.SIGHUP)  # the broker rereads the file itself; no /bin/kill needed
        return
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(levelname)s %(message)s")
    for warning in config.warnings:
        log.warning("%s: %s", config.source, warning)
    try:
        backend = make_backend(config.backend, config.backend_options)
    except FileNotFoundError as exc:  # age-keygen, bws, ... not on the service's PATH
        sys.exit(f"secret-brokerd: the {config.backend} store needs {exc.filename or exc}, which isn't installed or isn't on PATH")
    except (OSError, ValueError, TypeError, subprocess.CalledProcessError) as exc:
        sys.exit(f"secret-brokerd: the {config.backend} store can't start: {exc}")
    broker = Broker(config, backend)
    asyncio.run(broker.run())


if __name__ == "__main__":
    main()
