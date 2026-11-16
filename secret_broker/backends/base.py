from __future__ import annotations

from abc import ABC, abstractmethod


class NotConfigured(RuntimeError):
    """The store has no credential yet; the owner installs it with `sudo secret add <BOOTSTRAP_NAME>`."""


class Backend(ABC):
    """Where secret values live. Only the broker process talks to a backend."""

    @abstractmethod
    def names(self) -> list[str]: ...

    @abstractmethod
    def get(self, name: str) -> str | None: ...

    @abstractmethod
    def set(self, name: str, value: str) -> None: ...
