"""Broker decisions for peers the tests cannot be (root, uids outside allowed_uids)."""

import threading
import time

from secret_broker.backends.base import Backend
from secret_broker.daemon import Broker
from secret_broker.policy import parse_config


class StoreWithBootstrap(Backend):
    BOOTSTRAP_NAME = "BWS_ACCESS_TOKEN"

    def names(self):
        return []

    def get(self, name):
        return "dummy-value-123"

    def __init__(self):
        self.saved = {}

    def set(self, name, value):
        self.saved[name] = value

    def install_token(self, token):
        self.saved[self.BOOTSTRAP_NAME] = token


def broker(extra: str = "") -> Broker:
    return Broker(parse_config(extra + '[secrets.GH_TOKEN]\nallow = [["gh"]]\n'), StoreWithBootstrap())


def test_bootstrap_only_from_root():
    b = broker("allowed_uids = [1000]\n")
    reply = b.handle({"op": "request", "name": "BWS_ACCESS_TOKEN", "why": "x"}, uid=1000)
    assert reply["code"] == "denied" and "sudo secret add BWS_ACCESS_TOKEN" in reply["error"]
    # root is not in allowed_uids but may still install the store's own credential
    assert b.handle({"op": "request", "name": "BWS_ACCESS_TOKEN", "why": "x"}, uid=0)["ok"]
    assert b.handle({"op": "request", "name": "GH_TOKEN", "why": "x"}, uid=0)["code"] == "denied"


def test_run_needs_allowed_uids_and_never_targets_root():
    req = {"op": "run", "names": ["GH_TOKEN"], "argv": ["gh"], "env": {}}
    assert broker()._run(None, req, uid=1000, fds=[], rest=b"")["code"] == "denied"
    assert broker("allowed_uids = [0, 1000]\n")._run(None, req, uid=0, fds=[], rest=b"")["code"] == "denied"
    assert broker("allowed_uids = [1000]\n")._run(None, req, uid=1001, fds=[], rest=b"")["code"] == "denied"


def test_get_is_gone():
    reply = broker("allowed_uids = [1000]\n").handle({"op": "get", "names": ["GH_TOKEN"], "argv": ["gh"]}, uid=1000)
    assert not reply["ok"] and "values" not in reply and "dummy-value-123" not in str(reply)


def test_add_saves_the_typed_value():
    b = broker("allowed_uids = [1000]\n")
    assert b.handle({"op": "add", "name": "GH_TOKEN", "value": " ghp-typed-value \n"}, uid=1000) == {"ok": True}
    assert b.backend.saved == {"GH_TOKEN": "ghp-typed-value"}


def test_add_refuses_empty_values_bad_names_and_other_uids():
    b = broker("allowed_uids = [1000]\n")
    assert not b.handle({"op": "add", "name": "GH_TOKEN", "value": "  "}, uid=1000)["ok"]
    assert b.handle({"op": "add", "name": "GH_TOKEN", "value": "v"}, uid=1001)["code"] == "denied"
    assert b.backend.saved == {}


def test_add_of_the_store_credential_only_from_root():
    b = broker("allowed_uids = [1000]\n")
    reply = b.handle({"op": "add", "name": "BWS_ACCESS_TOKEN", "value": "attacker-token"}, uid=1000)
    assert reply["code"] == "denied" and b.backend.saved == {}
    assert b.handle({"op": "add", "name": "BWS_ACCESS_TOKEN", "value": "machine-token"}, uid=0)["ok"]
    assert b.backend.saved == {"BWS_ACCESS_TOKEN": "machine-token"}


def test_wait_by_name_sees_only_the_callers_own_request():
    b = broker("allowed_uids = [1000, 1001]\n")
    assert b.handle({"op": "request", "name": "GH_TOKEN", "why": "x"}, uid=1000)["ok"]
    assert b.handle({"op": "status", "name": "GH_TOKEN"}, uid=1000)["state"] == "pending"
    assert b.handle({"op": "status", "name": "GH_TOKEN"}, uid=1001)["state"] == "unknown"


def test_request_and_list_carry_the_policy():
    b = broker("allowed_uids = [1000]\n")
    reply = b.handle({"op": "request", "name": "GH_TOKEN", "why": "x"}, uid=1000)
    assert reply["policy"] and reply["allow"] == "gh"
    assert not b.handle({"op": "request", "name": "OTHER", "why": "x"}, uid=1000)["policy"]
    [item] = b.handle({"op": "list"}, uid=1000)["names"]
    assert item == {"name": "GH_TOKEN", "stored": False, "policy": True, "allow": [["gh"]]}
    # the store's own credential needs no policy entry
    assert b.handle({"op": "request", "name": "BWS_ACCESS_TOKEN", "why": "x"}, uid=0)["policy"]


def test_wait_by_name_sees_an_earlier_link_used_after_the_newest():
    """The agent asked twice (or two agents of one user did) and the owner opened the first link."""
    b = broker("allowed_uids = [1000]\n")
    first = b.handle({"op": "request", "name": "GH_TOKEN", "why": "x"}, uid=1000)["token"]
    b.handle({"op": "request", "name": "GH_TOKEN", "why": "x"}, uid=1000)
    assert b.handle({"op": "status", "name": "GH_TOKEN"}, uid=1000)["state"] == "pending"
    b.pending[first].state, b.pending[first].stored_at = "stored", time.time()
    assert b.handle({"op": "status", "name": "GH_TOKEN"}, uid=1000)["state"] == "stored"


def test_wait_by_name_ignores_a_value_stored_before_the_newest_link():
    b = broker("allowed_uids = [1000]\n")
    old = b.handle({"op": "request", "name": "GH_TOKEN", "why": "x"}, uid=1000)["token"]
    b.pending[old].state, b.pending[old].stored_at = "stored", time.time() - 60
    b.handle({"op": "request", "name": "GH_TOKEN", "why": "rotate"}, uid=1000)
    assert b.handle({"op": "status", "name": "GH_TOKEN"}, uid=1000)["state"] == "pending"


def test_status_by_name_while_other_threads_add_requests():
    """Connection threads look requests up by name while others add them (without the lock this
    raised "dictionary changed size during iteration" about 50 times a second)."""
    b = broker("allowed_uids = [1000]\n")
    stop, errors = threading.Event(), []

    def add_requests():
        while not stop.is_set():
            b.handle({"op": "request", "name": "OTHER", "why": "x"}, uid=1000)

    writer = threading.Thread(target=add_requests)
    writer.start()
    try:
        deadline = time.time() + 1.5
        while time.time() < deadline:
            try:
                b.handle({"op": "status", "name": "GH_TOKEN"}, uid=1000)
            except RuntimeError as exc:
                errors.append(exc)
    finally:
        stop.set()
        writer.join()
    assert errors == []


def test_wait_sees_a_value_typed_with_secret_add():
    b = broker("allowed_uids = [1000]\n")
    b.handle({"op": "request", "name": "GH_TOKEN", "why": "x"}, uid=1000)
    assert b.handle({"op": "add", "name": "GH_TOKEN", "value": "typed"}, uid=1000)["ok"]
    assert b.handle({"op": "status", "name": "GH_TOKEN"}, uid=1000)["state"] == "stored"
