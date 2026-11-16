"""Best-effort removal of secret values (and their common encodings) from byte streams."""

from __future__ import annotations

import base64
import urllib.parse

MIN_LEN = 6


def _forms(value: str) -> set[str]:
    raw = value.encode()
    forms = {value}
    b64 = base64.b64encode(raw).decode()
    forms.add(b64)
    forms.add(b64.rstrip("="))
    url = base64.urlsafe_b64encode(raw).decode()
    forms.add(url)
    forms.add(url.rstrip("="))
    forms.add(urllib.parse.quote(value, safe=""))
    return {f for f in forms if len(f) >= MIN_LEN}


class Redactor:
    """Replace every occurrence of the given values with [REDACTED:NAME].

    feed() is stream-safe: it holds back the tail of a chunk when a value could straddle the
    chunk boundary; flush() releases what is left.
    """

    def __init__(self, values: dict[str, str]):
        self._patterns: list[tuple[bytes, bytes]] = []
        for name, value in values.items():
            if not value:
                continue
            for form in _forms(value):
                self._patterns.append((form.encode(), f"[REDACTED:{name}]".encode()))
        self._patterns.sort(key=lambda p: -len(p[0]))
        self._hold = max((len(p) for p, _ in self._patterns), default=1) - 1
        self._buf = b""

    def redact(self, data: bytes) -> bytes:
        for pattern, replacement in self._patterns:
            if pattern in data:
                data = data.replace(pattern, replacement)
        return data

    def feed(self, chunk: bytes) -> bytes:
        self._buf += chunk
        if not self._patterns:
            out, self._buf = self._buf, b""
            return out
        cut = self._buf.rfind(b"\n")
        if cut >= 0:
            emit, rest = self._buf[: cut + 1], self._buf[cut + 1 :]
        else:
            emit, rest = b"", self._buf
        if len(rest) > 4096 and self._hold:
            emit, rest = emit + rest[: -self._hold], rest[-self._hold :]
        self._buf = rest
        return self.redact(emit)

    def flush(self, final: bool = False) -> bytes:
        """Release buffered output. Before the end of the stream (final=False) a tail that could
        still grow into a value is kept back, so a value printed in pieces is never cut open."""
        if final or not self._patterns:
            out, self._buf = self.redact(self._buf), b""
            return out
        buf = self._buf
        cut = len(buf)
        for k in range(min(len(buf), self._hold), 0, -1):
            if any(p.startswith(buf[-k:]) for p, _ in self._patterns):
                cut = len(buf) - k
                break
        # Never split a complete value that starts before the cut.
        moved = True
        while moved:
            moved = False
            for p, _ in self._patterns:
                start = buf.find(p, max(0, cut - len(p) + 1))
                if 0 <= start < cut < start + len(p):
                    cut, moved = start, True
        out, self._buf = self.redact(buf[:cut]), buf[cut:]
        return out

    @property
    def pending(self) -> bool:
        return bool(self._buf)
