"""Bitwarden Secrets Manager through the official `bws` CLI.

The machine-account access token is read from a root-only file and handed to bws through the
environment. Secret keys are the broker's names. Values are cached briefly in memory.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

from .base import Backend, NotConfigured


class BwsBackend(Backend):
    def __init__(
        self,
        token_file: str,
        project_id: str | None = None,
        state_dir: str | None = None,
        bws: str = "bws",
        cache_seconds: int = 60,
        server_url: str | None = None,
    ):
        self.token_file = Path(token_file)
        self.project_id = project_id
        self.state_dir = Path(state_dir) if state_dir else self.token_file.parent / "bws-state"
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.bws = bws
        self.cache_seconds = cache_seconds
        self.server_url = server_url.rstrip("/") if server_url else None
        self._cache: dict[str, dict] = {}
        self._cache_at = None

    # Name of the pseudo-secret the broker's page accepts to install the machine token itself.
    BOOTSTRAP_NAME = "BWS_ACCESS_TOKEN"

    def configured(self) -> bool:
        return self.token_file.exists() and bool(self.token_file.read_text(encoding="utf-8").strip())

    def install_token(self, token: str) -> None:
        self.token_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = self.token_file.with_suffix(".tmp")
        tmp.write_text(token.strip() + "\n", encoding="utf-8")
        tmp.chmod(0o600)
        tmp.replace(self.token_file)
        self._cache_at = None

    def _env(self) -> dict[str, str]:
        if not self.configured():
            raise NotConfigured(
                f"Bitwarden Secrets Manager is not configured: no machine token in {self.token_file}. "
                "Install it as root with: sudo secret add BWS_ACCESS_TOKEN"
            )
        token = self.token_file.read_text(encoding="utf-8").strip()
        self._ensure_config()
        env = {
            "PATH": os.environ.get("PATH", "/run/current-system/sw/bin:/usr/bin:/bin"),
            "HOME": str(self.state_dir),
            "BWS_ACCESS_TOKEN": token,
            "BWS_CONFIG_FILE": str(self.state_dir / "config"),
        }
        return env

    def _ensure_config(self) -> None:
        """bws refuses to start when BWS_CONFIG_FILE is missing, and an empty file is not valid TOML.

        Without server_url the broker only creates a minimal file (bws then uses its default, US cloud) and
        leaves an existing one alone. With server_url (e.g. https://vault.bitwarden.eu) the file is the
        broker's: it is rewritten whenever its content differs.
        """
        config = self.state_dir / "config"
        if self.server_url:
            want = f'[profiles.default]\nserver_base = "{self.server_url}"\n'
        elif config.exists():
            return
        else:
            want = "[profiles]\n"
        if config.exists() and config.read_text(encoding="utf-8") == want:
            return
        tmp = config.with_suffix(".tmp")
        tmp.write_text(want, encoding="utf-8")
        tmp.chmod(0o600)
        tmp.replace(config)

    def _run(self, *args: str) -> str:
        proc = subprocess.run([self.bws, *args], env=self._env(), capture_output=True, text=True)
        if proc.returncode != 0:
            # bws error text never contains secret values; keep the first line only.
            raise RuntimeError(f"bws {args[0]} {args[1] if len(args) > 1 else ''} failed: {proc.stderr.strip().splitlines()[:1]}")
        return proc.stdout

    def _secrets(self, refresh: bool = False) -> dict[str, dict]:
        # None, not 0.0: monotonic time starts near zero at boot, so 0.0 would look fresh.
        if refresh or self._cache_at is None or time.monotonic() - self._cache_at > self.cache_seconds:
            args = ["secret", "list", "-o", "json"]
            if self.project_id:
                args.append(self.project_id)
            items = json.loads(self._run(*args) or "[]")
            self._cache = {item["key"]: item for item in items}
            self._cache_at = time.monotonic()
        return self._cache

    def names(self) -> list[str]:
        return sorted(self._secrets().keys())

    def get(self, name: str) -> str | None:
        item = self._secrets().get(name)
        if item is None:
            item = self._secrets(refresh=True).get(name)
        return None if item is None else item.get("value")

    def _target_project(self) -> str:
        if self.project_id:
            return self.project_id
        projects = json.loads(self._run("project", "list", "-o", "json") or "[]")
        if len(projects) != 1:
            names = ", ".join(p.get("name", "?") for p in projects) or "none"
            raise RuntimeError(f"bws backend needs project_id when the machine account sees {len(projects)} projects ({names})")
        return projects[0]["id"]

    def set(self, name: str, value: str) -> None:
        existing = self._secrets(refresh=True).get(name)
        if existing:
            self._run("secret", "edit", "--value", value, existing["id"])
        else:
            self._run("secret", "create", name, value, self._target_project())
        self._cache_at = None
