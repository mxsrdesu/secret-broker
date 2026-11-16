import base64
import urllib.parse

from secret_broker.redact import Redactor


def test_plain_and_encoded_forms():
    v = "ghp_abcdefghijklmnop123456"
    r = Redactor({"GH_TOKEN": v})
    assert r.redact(f"token={v} done".encode()) == b"token=[REDACTED:GH_TOKEN] done"
    assert r.redact(base64.b64encode(v.encode())) == b"[REDACTED:GH_TOKEN]"
    assert r.redact(urllib.parse.quote(v, safe="").encode()) == b"[REDACTED:GH_TOKEN]"


def test_stream_boundary_without_newline():
    v = "supersecretvalue"
    r = Redactor({"X": v})
    out = r.feed(b"prefix super")
    out += r.feed(b"secretvalue suffix\n")
    out += r.flush()
    assert out == b"prefix [REDACTED:X] suffix\n"


def test_lines_are_emitted_promptly():
    r = Redactor({"X": "abcdefgh"})
    assert r.feed(b"hello\nworld") == b"hello\n"
    assert r.pending
    assert r.flush() == b"world"


def test_no_values_passthrough():
    r = Redactor({})
    assert r.feed(b"anything") == b"anything"
    assert r.flush() == b""


def test_short_values_are_not_redacted():
    r = Redactor({"X": "ab"})
    assert r.redact(b"abab") == b"abab"


def test_idle_flush_never_releases_the_start_of_a_value():
    # A value printed in pieces with a pause in between: the idle flush must hold back any tail
    # that could still become a value, and only the final flush releases what is left.
    r = Redactor({"TOK": "s3cr3t-value-ABCDEF123"})
    out = r.feed(b"progress s3cr3t-val") + r.flush()
    out += r.feed(b"ue-ABCDEF123 done") + r.flush(final=True)
    assert b"s3cr3t" not in out and out == b"progress [REDACTED:TOK] done"


def test_idle_flush_releases_text_that_cannot_be_a_value():
    r = Redactor({"TOK": "s3cr3t-value-ABCDEF123"})
    assert r.feed(b"Password: ") + r.flush() == b"Password: "
