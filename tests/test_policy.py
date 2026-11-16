import pytest

from secret_broker.policy import check, parse_config

CFG = parse_config(
    """
backend = "agefile"
[secrets.GH_TOKEN]
allow = [["gh"]]
[secrets.GITLAB_TOKEN]
allow = [["glab"], ["git", "push"], ["git", "fetch"]]
"""
)


def test_allowed_program_and_prefix():
    assert check(CFG, ["GH_TOKEN"], ["gh", "auth", "status"]).allowed
    assert check(CFG, ["GITLAB_TOKEN"], ["git", "push", "origin", "main"]).allowed
    assert check(CFG, ["GITLAB_TOKEN"], ["/usr/bin/glab", "ci", "status"]).allowed


def test_prefix_mismatch_is_denied():
    d = check(CFG, ["GITLAB_TOKEN"], ["git", "log"])
    assert not d.allowed and "not allowed" in d.reason


def test_shells_and_printers_are_always_denied():
    for argv in (["sh", "-c", "echo $GH_TOKEN"], ["env"], ["printenv", "GH_TOKEN"], ["/bin/bash"], ["python3", "-c", "1"]):
        d = check(CFG, ["GH_TOKEN"], argv)
        assert not d.allowed and "never receive" in d.reason


def test_unknown_secret_is_denied():
    d = check(CFG, ["NOPE"], ["gh", "api"])
    assert not d.allowed and "no policy" in d.reason


def test_every_name_must_be_allowed():
    assert not check(CFG, ["GH_TOKEN", "GITLAB_TOKEN"], ["gh", "api"]).allowed


def test_empty_inputs():
    assert not check(CFG, [], ["gh"]).allowed
    assert not check(CFG, ["GH_TOKEN"], []).allowed


def test_bad_names_rejected():
    with pytest.raises(ValueError):
        parse_config('[secrets."bad-name"]\nallow=[["gh"]]\n')
    with pytest.raises(ValueError):
        parse_config("[secrets.OK]\nallow=[[]]\n")
