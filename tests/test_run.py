"""End-to-end: daemon with the agefile backend, value entered through the web page, `secret run`."""

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import textwrap
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from secret_broker.backends.agefile import AgeFileBackend

pytestmark = pytest.mark.skipif(shutil.which("age") is None or shutil.which("age-keygen") is None, reason="age not installed")

VALUE = "s3cr3t-value-ABCDEF123"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _script(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\n" + textwrap.dedent(body))
    path.chmod(0o755)


def start_daemon(tmp_path: Path, backend: str = "agefile", extra: str = ""):
    port = _free_port()
    sock = tmp_path / "sock"
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    _script(bindir / "show-env", """\
        printf 'value=%s\\n' "$TEST_TOKEN"
        printf 'err=%s\\n' "$TEST_TOKEN" >&2
    """)
    # coreutils (true, sleep, ...) must be reachable through the trusted path, not the caller's PATH.
    coreutils = os.path.dirname(os.path.realpath(shutil.which("true")))
    cfg = tmp_path / "policy.toml"
    cfg.write_text(textwrap.dedent(f"""
        socket = "{sock}"
        http_bind = "127.0.0.1:{port}"
        public_base_url = "http://127.0.0.1:{port}"
        request_ttl_minutes = 5
        backend = "{backend}"
        allowed_uids = [{os.getuid()}]
        trusted_path = ["{bindir}", "{coreutils}"]
        [backends.agefile]
        dir = "{tmp_path / 'store'}"
        identity = "{tmp_path / 'age.key'}"
        [backends.bws]
        token_file = "{tmp_path / 'bws' / 'token'}"
        bws = "{tmp_path / 'no-bws'}"
        [secrets.TEST_TOKEN]
        allow = [["show-env"], ["true"], ["git"], ["gh"]]
        deny = ["--hostname"]
    """) + textwrap.dedent(extra))
    env = dict(os.environ, SECRET_BROKER_CONFIG=str(cfg), SECRET_BROKER_SOCKET=str(sock), PATH=f"{bindir}:{os.environ['PATH']}")
    proc = subprocess.Popen([sys.executable, "-m", "secret_broker.daemon"], env=env, stderr=subprocess.PIPE, text=True)
    for _ in range(100):
        if sock.exists():
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1)
                break
            except Exception:
                pass
        time.sleep(0.1)
    else:
        proc.kill()
        pytest.fail("daemon did not start: " + proc.stderr.read())
    return proc, {"env": env, "port": port, "sock": sock, "bin": bindir, "tmp": tmp_path}


@pytest.fixture
def broker(tmp_path: Path):
    proc, info = start_daemon(tmp_path)
    yield info
    proc.terminate()
    proc.wait(timeout=10)


def secret(env, *args, **kw):
    return subprocess.run([sys.executable, "-m", "secret_broker.client", *args], env=env, capture_output=True, text=True, **kw)


def store(broker, name: str, value: str) -> None:
    """Seed the daemon's store directly; the page flow has its own test above."""
    AgeFileBackend(dir=str(broker["tmp"] / "store"), identity=str(broker["tmp"] / "age.key")).set(name, value)


def raw(sock: Path, request: dict) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect(str(sock))
        s.sendall(json.dumps(request).encode() + b"\n")
        buf = b""
        while chunk := s.recv(65536):
            buf += chunk
    return buf


def test_request_store_run_redact(broker):
    env = broker["env"]
    r = secret(env, "request", "TEST_TOKEN", "--why", "test", "--no-wait")
    assert r.returncode == 0, r.stderr
    url = [l for l in r.stdout.splitlines() if l.startswith("http")][0]
    page = urllib.request.urlopen(url, timeout=5).read().decode()
    check = page.split('name="check" value="')[1].split('"')[0]
    # a stale form is refused without storing anything
    stale = urllib.request.Request(url, data=f"check=wrong&value={VALUE}".encode(), method="POST")
    with pytest.raises(urllib.error.HTTPError) as err:
        urllib.request.urlopen(stale, timeout=5)
    assert err.value.code == 400 and "out of date" in err.value.read().decode()
    data = f"check={check}&value={VALUE}".encode()
    resp = urllib.request.urlopen(urllib.request.Request(url, data=data, method="POST"), timeout=5)
    body = resp.read().decode()
    assert resp.status == 200 and "TEST_TOKEN</span> saved" in body and VALUE not in body
    # the link is one-time
    assert "already" in urllib.request.urlopen(url, timeout=5).read().decode().lower()

    ls = secret(env, "ls")
    assert "TEST_TOKEN" in ls.stdout and "stored" in ls.stdout and VALUE not in ls.stdout

    run = secret(env, "run", "TEST_TOKEN", "--", "show-env")
    assert run.returncode == 0, run.stderr
    assert run.stdout == "value=[REDACTED:TEST_TOKEN]\n"
    assert run.stderr == "err=[REDACTED:TEST_TOKEN]\n"
    assert VALUE not in run.stdout + run.stderr


def test_denials(broker):
    env = broker["env"]
    r = secret(env, "run", "TEST_TOKEN", "--", "sh", "-c", "echo $TEST_TOKEN")
    assert r.returncode == 77 and "never receive" in r.stderr
    r = secret(env, "run", "TEST_TOKEN", "--", "false")
    assert r.returncode == 77 and "not allowed" in r.stderr
    r = secret(env, "run", "NOPE", "--", "true")
    assert r.returncode == 77 and "no policy" in r.stderr


def test_missing_value_message(broker):
    env = broker["env"]
    r = secret(env, "run", "TEST_TOKEN", "--", "true")
    assert r.returncode == 78 and "not stored yet" in r.stderr and "secret request TEST_TOKEN" in r.stderr


def test_exit_code_passthrough(broker):
    env = broker["env"]
    store(broker, "TEST_TOKEN", "abcdefgh")
    _script(broker["bin"] / "show-env", "exit 42\n")
    assert secret(env, "run", "TEST_TOKEN", "--", "show-env").returncode == 42


def test_raw_get_returns_no_value(broker):
    store(broker, "TEST_TOKEN", VALUE)
    reply = raw(broker["sock"], {"op": "get", "names": ["TEST_TOKEN"], "argv": ["show-env"]})
    assert VALUE.encode() not in reply
    assert not json.loads(reply.split(b"\n")[0])["ok"]


def test_raw_run_without_fds_is_refused(broker, tmp_path):
    store(broker, "TEST_TOKEN", VALUE)
    marker = tmp_path / "ran"
    _script(broker["bin"] / "show-env", f"touch {marker}\nprintf '%s\\n' \"$TEST_TOKEN\"\n")
    reply = raw(broker["sock"], {"op": "run", "names": ["TEST_TOKEN"], "argv": ["show-env"], "env": {}})
    assert VALUE.encode() not in reply
    assert not json.loads(reply.split(b"\n")[0])["ok"]
    assert not marker.exists()


def test_fake_binary_outside_trusted_path_is_denied(broker, tmp_path):
    env = broker["env"]
    store(broker, "TEST_TOKEN", VALUE)
    fake = tmp_path / "work"
    fake.mkdir()
    _script(fake / "show-env", "printf 'FAKE %s\\n' \"$TEST_TOKEN\"\n")
    r = secret(env, "run", "TEST_TOKEN", "--", "./show-env", cwd=fake)
    assert r.returncode == 77 and "trusted" in r.stderr and "FAKE" not in r.stdout
    # A fake earlier on the caller's PATH is ignored: the daemon resolves through trusted_path.
    r = secret(dict(env, PATH=f"{fake}:{env['PATH']}"), "run", "TEST_TOKEN", "--", "show-env", cwd=fake)
    assert r.returncode == 0 and r.stdout == "value=[REDACTED:TEST_TOKEN]\n"
    # An absolute path is fine when its directory is trusted.
    r = secret(env, "run", "TEST_TOKEN", "--", str(broker["bin"] / "show-env"))
    assert r.returncode == 0 and r.stdout == "value=[REDACTED:TEST_TOKEN]\n"


def test_child_gets_cwd_stdin_and_scrubbed_env(broker, tmp_path):
    env = dict(broker["env"], LD_FOO="x", GIT_SSH_COMMAND="x", GIT_CONFIG_KEY_0="x", GIT_CONFIG_COUNT="1", GIT_ASKPASS="x", PAGER="x", KEEP_ME="kept")
    store(broker, "TEST_TOKEN", VALUE)
    _script(broker["bin"] / "show-env", """\
        read line
        printf 'stdin=%s\\n' "$line"
        printf 'cwd=%s\\n' "$(pwd)"
        printf 'path=%s\\n' "$PATH"
        printf 'leak=%s%s%s%s%s%s\\n' "$LD_FOO" "$GIT_SSH_COMMAND" "$GIT_CONFIG_KEY_0" "$GIT_CONFIG_COUNT" "$GIT_ASKPASS" "$PAGER"
        while read -r key val; do [ "$key" = NoNewPrivs: ] && printf 'nnp=%s\\n' "$val"; done < /proc/self/status
        printf 'keep=%s\\n' "$KEEP_ME"
    """)
    work = tmp_path / "work"
    work.mkdir()
    r = secret(env, "run", "TEST_TOKEN", "--", "show-env", cwd=work, input="hello\n")
    assert r.returncode == 0, r.stderr
    lines = dict(l.split("=", 1) for l in r.stdout.splitlines())
    assert lines["stdin"] == "hello"
    assert os.path.realpath(lines["cwd"]) == os.path.realpath(work)
    assert lines["path"].split(":")[0] == str(broker["bin"]) and str(work) not in lines["path"]
    assert lines["leak"] == "" and lines["keep"] == "kept"
    assert lines["nnp"] == "1"


def test_signal_forwarded_and_disconnect_terminates(broker, tmp_path):
    env = broker["env"]
    store(broker, "TEST_TOKEN", VALUE)
    pidfile = tmp_path / "pid"
    _script(broker["bin"] / "show-env", f"echo $$ > {pidfile}\nexec sleep 30\n")
    client = [sys.executable, "-m", "secret_broker.client", "run", "TEST_TOKEN", "--", "show-env"]

    def start():
        pidfile.unlink(missing_ok=True)
        p = subprocess.Popen(client, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for _ in range(100):
            if pidfile.exists() and pidfile.read_text().strip():
                return p, int(pidfile.read_text())
            time.sleep(0.05)
        p.kill()
        pytest.fail("child did not start")

    p, _child = start()
    p.send_signal(signal.SIGTERM)
    assert p.wait(timeout=10) == 128 + signal.SIGTERM

    p, child = start()
    p.kill()  # no chance to forward anything: the daemon notices the closed connection
    p.wait(timeout=10)
    for _ in range(100):
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        pytest.fail("child survived the client disconnect")


@pytest.mark.parametrize("argv, offending", [
    (["git", "-c", "core.sshCommand=x", "push"], "-c"),
    (["git", "push", "-ccore.pager=x"], "-ccore.pager=x"),
    (["git", "fetch", "--upload-pack=x"], "--upload-pack=x"),
    (["git", "--exec-path=/tmp", "push"], "--exec-path=/tmp"),
    (["gh", "alias", "set", "x", "!sh"], "alias"),
    (["gh", "extension", "install", "x"], "extension"),
    (["gh", "api", "--hostname=evil.example"], "--hostname=evil.example"),
    (["gh", "api", "--hostname", "evil.example"], "--hostname"),
])
def test_argument_denials(broker, argv, offending):
    r = secret(broker["env"], "run", "TEST_TOKEN", "--", *argv)
    assert r.returncode == 77 and f"'{offending}'" in r.stderr


def test_bootstrap_request_from_non_root_is_refused(tmp_path):
    proc, info = start_daemon(tmp_path, backend="bws")
    try:
        r = secret(info["env"], "request", "BWS_ACCESS_TOKEN", "--why", "bootstrap", "--no-wait")
        assert r.returncode == 77 and "sudo secret add BWS_ACCESS_TOKEN" in r.stderr and "http" not in r.stdout
        r = subprocess.run([sys.executable, "-m", "secret_broker.daemon", "bootstrap"], env=info["env"], capture_output=True, text=True)
        assert r.returncode != 0 and "sudo secret add BWS_ACCESS_TOKEN" in r.stderr
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_add_at_a_terminal_then_run(broker):
    """`secret add` reads the value from a real terminal and the next `secret run` gets it."""
    import pty

    pid, fd = pty.fork()
    if pid == 0:
        os.execve(sys.executable, [sys.executable, "-m", "secret_broker.client", "add", "TEST_TOKEN"], broker["env"])
    out = b""
    while b"TEST_TOKEN:" not in out:
        out += os.read(fd, 1024)
    os.write(fd, VALUE.encode() + b"\n")
    while True:
        try:
            chunk = os.read(fd, 1024)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0, out
    assert b"saved TEST_TOKEN" in out and VALUE.encode() not in out  # the prompt doesn't echo
    run = secret(broker["env"], "run", "TEST_TOKEN", "--", "show-env")
    assert run.returncode == 0 and run.stdout == "value=[REDACTED:TEST_TOKEN]\n"


def test_add_without_a_terminal_is_refused(broker):
    r = secret(broker["env"], "add", "TEST_TOKEN", input=VALUE + "\n")
    assert r.returncode == 2 and "secret request" in r.stderr
    assert "TEST_TOKEN  not stored" in secret(broker["env"], "ls").stdout


def test_page_says_when_the_store_is_not_set_up(tmp_path):
    proc, info = start_daemon(tmp_path, backend="bws")
    try:
        r = secret(info["env"], "request", "TEST_TOKEN", "--why", "test", "--no-wait")
        url = [l for l in r.stdout.splitlines() if l.startswith("http")][0]
        check = urllib.request.urlopen(url, timeout=5).read().decode().split('name="check" value="')[1].split('"')[0]
        post = urllib.request.Request(url, data=f"check={check}&value={VALUE}".encode(), method="POST")
        with pytest.raises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(post, timeout=5)
        body = err.value.read().decode()
        assert err.value.code == 500 and "connected on" in body and "sudo secret add BWS_ACCESS_TOKEN" in body
        assert VALUE not in body
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def enter_value(url: str, value: str) -> None:
    """What the owner does on the page: open the link, submit the form."""
    check = urllib.request.urlopen(url, timeout=5).read().decode().split('name="check" value="')[1].split('"')[0]
    post = urllib.request.Request(url, data=f"check={check}&value={value}".encode(), method="POST")
    assert urllib.request.urlopen(post, timeout=5).status == 200


def test_request_without_a_terminal_returns_and_wait_picks_it_up(broker):
    env = broker["env"]
    started = time.time()
    r = secret(env, "request", "TEST_TOKEN", "--why", "test")  # no --no-wait: stdout isn't a terminal
    assert r.returncode == 0 and time.time() - started < 10, r.stderr
    url = [l for l in r.stdout.splitlines() if l.startswith("http")][0]
    assert "secret wait TEST_TOKEN" in r.stdout and "no policy" not in r.stderr
    w = secret(env, "wait", "TEST_TOKEN", "--timeout", "1")
    assert w.returncode == 75 and "secret wait TEST_TOKEN" in w.stderr
    enter_value(url, VALUE)
    w = secret(env, "wait", "TEST_TOKEN")
    assert w.returncode == 0 and w.stdout == "stored TEST_TOKEN\n"
    assert VALUE not in r.stdout + r.stderr + w.stdout + w.stderr


def test_wait_without_a_request(broker):
    w = secret(broker["env"], "wait", "TEST_TOKEN", "--timeout", "1")
    assert w.returncode == 1 and "secret request TEST_TOKEN" in w.stderr


def test_request_names_the_missing_policy_entry(broker):
    r = secret(broker["env"], "request", "NEW_TOKEN", "--why", "test")
    assert r.returncode == 0 and "http" in r.stdout
    assert "[secrets.NEW_TOKEN]" in r.stderr and "systemctl reload secret-broker" in r.stderr


def test_ls_and_refusals_name_the_allowed_commands(broker):
    ls = secret(broker["env"], "ls").stdout
    assert "TEST_TOKEN  not stored  show-env; true; git; gh" in ls
    r = secret(broker["env"], "run", "TEST_TOKEN", "--", "false")
    assert r.returncode == 77 and "allowed: show-env; true; git; gh" in r.stderr
    r = secret(broker["env"], "run", "NOPE", "--", "true")
    assert r.returncode == 77 and "[secrets.NOPE]" in r.stderr and "policy.toml" in r.stderr


def test_sighup_reloads_the_policy_without_stopping_a_running_command(tmp_path):
    proc, info = start_daemon(tmp_path)
    try:
        env, cfg = info["env"], tmp_path / "policy.toml"
        store(info, "TEST_TOKEN", VALUE)
        store(info, "NEW_TOKEN", VALUE + "2")
        _script(info["bin"] / "show-env", "sleep 2\nprintf 'value=%s\\n' \"$TEST_TOKEN$NEW_TOKEN\"\n")
        running = subprocess.Popen(
            [sys.executable, "-m", "secret_broker.client", "run", "TEST_TOKEN", "--", "show-env"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        time.sleep(0.5)
        assert secret(env, "run", "NEW_TOKEN", "--", "true").returncode == 77
        good = cfg.read_text()
        cfg.write_text(good + '[secrets.NEW_TOKEN]\nallow = [["show-env"]]\n')
        check = [sys.executable, "-m", "secret_broker.daemon", "check", "--reload", str(proc.pid)]
        assert subprocess.run(check, env=env, capture_output=True, text=True).returncode == 0  # what systemctl reload runs
        time.sleep(0.5)
        r = secret(env, "run", "NEW_TOKEN", "--", "show-env")
        assert r.returncode == 0 and r.stdout == "value=[REDACTED:NEW_TOKEN]\n", r.stderr
        out, err = running.communicate(timeout=10)
        assert running.returncode == 0 and out == "value=[REDACTED:TEST_TOKEN]\n", err
        # A broken file is refused; the policy loaded before stays.
        cfg.write_text("this is not toml [")
        proc.send_signal(signal.SIGHUP)
        time.sleep(0.5)
        assert proc.poll() is None
        r = secret(env, "run", "NEW_TOKEN", "--", "show-env")
        assert r.returncode == 0 and r.stdout == "value=[REDACTED:NEW_TOKEN]\n", r.stderr
        bad = subprocess.run(check, env=env, capture_output=True, text=True)
        assert bad.returncode == 1 and "policy.toml" in bad.stderr and "Traceback" not in bad.stderr
    finally:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.mark.parametrize("policy, message", [
    ('allowed_uids = [1000]\n', "[backends.agefile] needs dir, identity"),
    ('backend = "vault"\n', "unknown backend 'vault'"),
    ('backend = "bws"\n[backends.bws]\nproject = "x"\n', "[backends.bws] has unknown key(s): project"),
    ('[secrets.GH_TOKEN]\nallow = "gh"\n', "secrets.GH_TOKEN.allow must be a list"),
    ('socket = \n', "policy.toml"),
    ('request_ttl_minutes = "15"\n', "request_ttl_minutes must be a whole number"),
    ('public_base_url = 5\n', "public_base_url must be a string"),
    ('allowed_uids = "1000"\n', "allowed_uids must be a list of user ids"),
    ('allowed_uids = 1000\n', "allowed_uids must be a list of user ids"),
    ('http_bind = "8787"\n', 'http_bind must be "host:port"'),
    ('backends = 1\n', "backends must be a table"),
    ('[secrets]\nGH_TOKEN = "gh"\n', "secrets.GH_TOKEN must be a table"),
    ('[backends.agefile]\ndir = 5\nidentity = "/x"\n', "[backends.agefile] dir must be a string"),
    ('backend = "bws"\n[backends.bws]\ntoken_file = "/x"\ncache_seconds = "60"\n', "[backends.bws] cache_seconds must be a whole number"),
])
def test_a_bad_policy_is_one_line_not_a_traceback(tmp_path, policy, message):
    cfg = tmp_path / "policy.toml"
    cfg.write_text(policy)
    env = dict(os.environ, SECRET_BROKER_CONFIG=str(cfg))
    for args in ([], ["check"]):
        r = subprocess.run([sys.executable, "-m", "secret_broker.daemon", *args], env=env, capture_output=True, text=True, timeout=20)
        assert r.returncode == 1 and message in r.stderr and "Traceback" not in r.stderr, r.stderr


def test_check_accepts_a_good_policy(tmp_path):
    proc, info = start_daemon(tmp_path)
    proc.terminate()
    proc.wait(timeout=10)
    r = subprocess.run([sys.executable, "-m", "secret_broker.daemon", "check"], env=info["env"], capture_output=True, text=True)
    assert r.returncode == 0 and "ok, backend agefile, 1 secret(s)" in r.stdout


def test_ready_is_sent_to_systemd_once_both_sockets_accept(tmp_path, monkeypatch):
    """Type=notify: systemd holds start and reload until READY=1, so it must mean "connect now"."""
    notify = tmp_path / "notify"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    listener.bind(str(notify))
    monkeypatch.setenv("NOTIFY_SOCKET", str(notify))
    proc, info = start_daemon(tmp_path)
    try:
        listener.settimeout(10)
        assert listener.recv(100) == b"READY=1"
        assert secret(info["env"], "status").returncode == 0
        urllib.request.urlopen(f"http://127.0.0.1:{info['port']}/healthz", timeout=2)
    finally:
        listener.close()
        proc.terminate()
        proc.wait(timeout=10)


def test_check_names_unknown_keys(tmp_path):
    """A typo such as allowed_uid would silently leave the uid gate open; check says so."""
    cfg = tmp_path / "policy.toml"
    cfg.write_text('allowed_uid = [1000]\n[backends.agefile]\ndir = "/x"\nidentity = "/y"\n[secrets.GH_TOKEN]\nallowed = [["gh"]]\n')
    r = subprocess.run([sys.executable, "-m", "secret_broker.daemon", "check"], env=dict(os.environ, SECRET_BROKER_CONFIG=str(cfg)), capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "unknown key allowed_uid is ignored" in r.stderr and "unknown key secrets.GH_TOKEN.allowed is ignored" in r.stderr
