import ast
import os
import socket
import subprocess

import pytest
from conftest import PROJECT_DIR
from guard import Blocked

NETWORK_MODULES = {"socket", "ssl", "http", "urllib", "dns"}
API_METHODS = ("shodan", "onyphe", "internetdb", "otx", "virustotal", "urlscan", "mnemonic")


def _imports(path):
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), path)
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module.split(".")[0])
    return found


@pytest.mark.parametrize("name", API_METHODS)
def test_api_methods_import_no_network_module(name):
    path = os.path.join(PROJECT_DIR, "ip2fqdn", "methods", f"{name}.py")
    if not os.path.exists(path):
        pytest.skip("method not written yet")
    assert _imports(path) & NETWORK_MODULES == set()


def test_connection_outside_loopback_range_blocked():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock, pytest.raises(Blocked):
        sock.connect(("127.0.0.1", 4000))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock, pytest.raises(Blocked):
        sock.connect(("192.0.2.1", 443))


def test_low_port_blocked():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock, pytest.raises(Blocked):
        sock.connect(("127.0.1.1", 443))


def test_allowed_connection_reaches_socket():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock, \
            pytest.raises(ConnectionRefusedError):
        sock.connect(("127.0.1.1", 1999))


def test_name_lookup_blocked():
    with pytest.raises(Blocked):
        socket.getaddrinfo("example.com", 80)
    assert socket.getaddrinfo("127.0.1.1", 2000)


def test_program_launch_blocked():
    with pytest.raises(Blocked):
        subprocess.run(["true"], check=False)
    with pytest.raises(Blocked):
        os.system("true")
