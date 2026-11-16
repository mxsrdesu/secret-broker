"""What `secret` says when it can't reach the broker: a sandbox and a missing group are different fixes."""

import errno
import os
import socket
from unittest import mock

import pytest

from secret_broker.protocol import BrokerError, connect


def test_a_sandbox_that_forbids_unix_sockets(tmp_path):
    # Claude Code's seccomp filter refuses socket() itself.
    with mock.patch("secret_broker.protocol.socket.socket", side_effect=PermissionError(errno.EPERM, "Operation not permitted")):
        with pytest.raises(BrokerError) as err:
            connect(str(tmp_path / "sock"))
    assert "\"secret *\" to sandbox.excludedCommands" in str(err.value) and "group" not in str(err.value)


def test_a_sandbox_that_forbids_connect(tmp_path):
    # Codex's filter lets socket() through and refuses connect().
    real = socket.socket

    class Refusing(real):
        def connect(self, _addr):
            raise PermissionError(errno.EPERM, "Operation not permitted")

    with mock.patch("secret_broker.protocol.socket.socket", Refusing):
        with pytest.raises(BrokerError) as err:
            connect(str(tmp_path / "sock"))
    assert "network_access = true" in str(err.value) and "group" not in str(err.value)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_no_access_to_the_socket_directory_means_the_group(tmp_path):
    rundir = tmp_path / "run"
    rundir.mkdir()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(rundir / "sock"))
        server.listen(1)
        rundir.chmod(0)
        try:
            with pytest.raises(BrokerError) as err:
                connect(str(rundir / "sock"))
        finally:
            rundir.chmod(0o700)
    assert "secret-broker group" in str(err.value) and "sandbox" not in str(err.value)


def test_no_broker_running(tmp_path):
    with pytest.raises(BrokerError) as err:
        connect(str(tmp_path / "sock"))
    assert "systemctl status secret-broker" in str(err.value)
