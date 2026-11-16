"""One age-encrypted file per secret. Used for local development, tests and as an offline store."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from .base import Backend


class AgeFileBackend(Backend):
    def __init__(self, dir: str, identity: str, age: str = "age", age_keygen: str = "age-keygen"):
        self.dir = Path(dir)
        self.identity = Path(identity)
        self.age = age
        self.age_keygen = age_keygen
        self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not self.identity.exists():
            # age-keygen refuses to overwrite; it creates the file itself with mode 0600.
            self.identity.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            subprocess.run([self.age_keygen, "-o", str(self.identity)], check=True, capture_output=True)
            os.chmod(self.identity, 0o600)
        self._recipient = subprocess.run(
            [self.age_keygen, "-y", str(self.identity)], check=True, capture_output=True, text=True
        ).stdout.strip()

    def _path(self, name: str) -> Path:
        return self.dir / f"{name}.age"

    def names(self) -> list[str]:
        return sorted(p.name[: -len(".age")] for p in self.dir.glob("*.age"))

    def get(self, name: str) -> str | None:
        path = self._path(name)
        if not path.exists():
            return None
        out = subprocess.run(
            [self.age, "-d", "-i", str(self.identity), str(path)], check=True, capture_output=True
        ).stdout
        return out.decode("utf-8")

    def set(self, name: str, value: str) -> None:
        path = self._path(name)
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=f".{name}.", suffix=".tmp")
        os.close(fd)
        try:
            subprocess.run(
                [self.age, "-r", self._recipient, "-o", tmp], input=value.encode("utf-8"), check=True, capture_output=True
            )
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
