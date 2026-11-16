"""Configuration and the per-secret command allowlist."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import PurePosixPath

DEFAULT_CONFIG = "/etc/secret-broker/policy.toml"
CONFIG_ENV = "SECRET_BROKER_CONFIG"
SOCKET_ENV = "SECRET_BROKER_SOCKET"

# Programs that can turn an injected value into output no matter what follows them.
FORBIDDEN_PROGRAMS = frozenset(
    {
        "sh", "bash", "zsh", "fish", "dash", "ksh", "csh", "tcsh", "busybox",
        "env", "sudo", "su", "doas", "nohup", "setsid", "xargs", "script", "time", "timeout", "nice",
        "python", "python3", "node", "nodejs", "bun", "deno", "perl", "ruby", "php", "lua", "awk", "gawk",
        "printenv", "export", "set", "echo", "printf", "cat", "tee", "strace", "ltrace", "gdb",
    }
)

# Arguments that make git run a command or load config of the caller's choosing.
GIT_DENIED_PREFIXES = ("-c", "--config-env", "--exec-path", "--receive-pack", "--upload-pack", "--exec")
# gh subcommands that define or install new commands.
GH_DENIED_SUBCOMMANDS = frozenset({"alias", "extension", "extensions", "ext"})

# Where the daemon looks for programs; {user} is the peer's user name. NixOS profiles first, then the
# root-owned directories of other distributions. Never a directory the user can write to.
DEFAULT_TRUSTED_PATH = (
    "/run/wrappers/bin", "/run/current-system/sw/bin", "/etc/profiles/per-user/{user}/bin",
    "/usr/local/bin", "/usr/bin", "/bin",
)


@dataclass(frozen=True)
class SecretPolicy:
    name: str
    allow: tuple[tuple[str, ...], ...]
    description: str = ""
    # Argument tokens never passed with this secret: an exact match or token=...
    deny: tuple[str, ...] = ()


@dataclass
class Config:
    socket: str = "/run/secret-broker/sock"
    http_bind: str = "127.0.0.1:8787"
    public_base_url: str = "http://127.0.0.1:8787"
    request_ttl_minutes: int = 15
    backend: str = "agefile"
    backend_options: dict = field(default_factory=dict)
    secrets: dict[str, SecretPolicy] = field(default_factory=dict)
    # None = every peer that can open the socket (the socket mode/group is the gate); `run` needs a list.
    allowed_uids: tuple[int, ...] | None = None
    trusted_path: tuple[str, ...] = DEFAULT_TRUSTED_PATH
    # The file this config came from; named in messages that ask the owner to edit it.
    source: str = DEFAULT_CONFIG
    # Keys the broker doesn't know (a typo like allowed_uid): ignored, but `check` and the log name them.
    warnings: list[str] = field(default_factory=list)

    @property
    def http_host(self) -> str:
        return self.http_bind.rsplit(":", 1)[0]

    @property
    def http_port(self) -> int:
        return int(self.http_bind.rsplit(":", 1)[1])


def config_path() -> str:
    return os.environ.get(CONFIG_ENV, DEFAULT_CONFIG)


def socket_path(config: Config | None = None) -> str:
    env = os.environ.get(SOCKET_ENV)
    if env:
        return env
    return config.socket if config else Config().socket


TOP_LEVEL_KEYS = (
    "socket", "http_bind", "public_base_url", "request_ttl_minutes", "backend", "allowed_uids",
    "trusted_path", "backends", "secrets",
)
SECRET_KEYS = ("allow", "deny", "description")


def _table(value: object, key: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be a table, like [{key}]")
    return value


def parse_config(text: str) -> Config:
    """The policy file. A wrong type is reported here, by key, rather than failing the first request."""
    raw = tomllib.loads(text)
    cfg = Config()
    for key in raw:
        if key not in TOP_LEVEL_KEYS:
            cfg.warnings.append(f"unknown key {key} is ignored; known: {', '.join(TOP_LEVEL_KEYS)}")
    for key in ("socket", "http_bind", "public_base_url", "backend"):
        if key in raw:
            if not isinstance(raw[key], str) or not raw[key]:
                raise ValueError(f"{key} must be a string")
            setattr(cfg, key, raw[key])
    if "http_bind" in raw:
        host, _, port = cfg.http_bind.rpartition(":")
        if not host or not port.isdigit() or not 0 < int(port) < 65536:
            raise ValueError('http_bind must be "host:port", like "127.0.0.1:8787"')
    if "request_ttl_minutes" in raw:
        ttl = raw["request_ttl_minutes"]
        if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 1:
            raise ValueError("request_ttl_minutes must be a whole number of minutes, 1 or more")
        cfg.request_ttl_minutes = ttl
    if "allowed_uids" in raw:
        uids = raw["allowed_uids"]
        if not isinstance(uids, list) or not all(isinstance(u, int) and not isinstance(u, bool) and u >= 0 for u in uids):
            raise ValueError("allowed_uids must be a list of user ids, like [1000]")
        cfg.allowed_uids = tuple(uids)
    if "trusted_path" in raw:
        trusted = raw["trusted_path"]
        if not isinstance(trusted, list) or not all(isinstance(d, str) and d.startswith("/") for d in trusted):
            raise ValueError("trusted_path must be a list of absolute directories")
        cfg.trusted_path = tuple(trusted)
    backends = _table(raw.get("backends", {}), "backends")
    cfg.backend_options = dict(_table(backends.get(cfg.backend, {}), f"backends.{cfg.backend}"))
    for name, body in _table(raw.get("secrets", {}), "secrets").items():
        _validate_name(name)
        body = _table(body, f"secrets.{name}")
        for key in body:
            if key not in SECRET_KEYS:
                cfg.warnings.append(f"unknown key secrets.{name}.{key} is ignored; known: {', '.join(SECRET_KEYS)}")
        allow = body.get("allow", [])
        if not isinstance(allow, list) or not all(isinstance(p, list) and p and all(isinstance(s, str) for s in p) for p in allow):
            raise ValueError(f"secrets.{name}.allow must be a list of non-empty argv prefixes")
        deny = body.get("deny", [])
        if not isinstance(deny, list) or not all(isinstance(t, str) and t for t in deny):
            raise ValueError(f"secrets.{name}.deny must be a list of argument tokens")
        cfg.secrets[name] = SecretPolicy(
            name=name,
            allow=tuple(tuple(p) for p in allow),
            description=str(body.get("description", "")),
            deny=tuple(deny),
        )
    return cfg


def load_config(path: str | None = None) -> Config:
    path = path or config_path()
    with open(path, "rb") as fh:
        cfg = parse_config(fh.read().decode("utf-8"))
    cfg.source = path
    return cfg


def _validate_name(name: str) -> None:
    if not name or not all(c.isalnum() or c == "_" for c in name) or name[0].isdigit():
        raise ValueError(f"invalid secret name {name!r}: use UPPER_SNAKE_CASE identifiers")


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return self.allowed


def check(config: Config, names: list[str], argv: list[str]) -> Decision:
    """Decide whether `argv` may receive the secrets `names` in its environment."""
    if not argv:
        return Decision(False, "no command given")
    if not names:
        return Decision(False, "no secret names given")
    program = PurePosixPath(argv[0]).name
    if not program or program in FORBIDDEN_PROGRAMS:
        return Decision(False, f"'{program or argv[0]}' is a shell, interpreter or printer; it can never receive secrets")
    for name in names:
        policy = config.secrets.get(name)
        if policy is None:
            return Decision(False, no_policy_hint(name, config.source))
        if not any(_matches(prefix, program, argv) for prefix in policy.allow):
            return Decision(
                False,
                f"{name} is not allowed for '{' '.join(argv[:3])}{' …' if len(argv) > 3 else ''}'; "
                f"allowed: {allowed_commands(policy)}",
            )
    args = argv[1:]
    if program == "git":
        for arg in args:
            if arg.startswith(GIT_DENIED_PREFIXES):
                return Decision(False, f"git argument '{arg}' can run arbitrary commands; it is never allowed with secrets")
    if program == "gh" and args[:1] and args[0] in GH_DENIED_SUBCOMMANDS:
        return Decision(False, f"gh subcommand '{args[0]}' can define new commands; it is never allowed with secrets")
    for name in names:
        for token in config.secrets[name].deny:
            for arg in args:
                if arg == token or arg.startswith(token + "="):
                    return Decision(False, f"argument '{arg}' is denied for {name}")
    return Decision(True, "allowed")


def allowed_commands(policy: SecretPolicy) -> str:
    """The allow list as people write commands: `gh; git push`."""
    return "; ".join(" ".join(prefix) for prefix in policy.allow) or "nothing"


def no_policy_hint(name: str, path: str = DEFAULT_CONFIG) -> str:
    return (
        f"{name} has no policy entry, so no command may receive it. The owner adds it to {path}, "
        f'e.g. [secrets.{name}] allow = [["<program>"]], then runs: sudo systemctl reload secret-broker'
    )


def _matches(prefix: tuple[str, ...], program: str, argv: list[str]) -> bool:
    if PurePosixPath(prefix[0]).name != program:
        return False
    rest = prefix[1:]
    return tuple(argv[1 : 1 + len(rest)]) == rest
