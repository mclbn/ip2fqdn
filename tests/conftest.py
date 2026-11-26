import logging
import os
import sys
import time

import pytest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(TESTS_DIR)
DATA_DIR = os.path.join(TESTS_DIR, "data")
SITE_DIR = os.path.join(TESTS_DIR, "sitecustomize")
os.environ["PYTHONASYNCIODEBUG"] = "1"
for path in (PROJECT_DIR, TESTS_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

import guard


class _SlowCallbacks(logging.Handler):
    def __init__(self):
        super().__init__(logging.WARNING)
        self.messages = []

    def emit(self, record):
        message = record.getMessage()
        if message.startswith("Executing ") and " took " in message:
            self.messages.append(message)


SLOW = _SlowCallbacks()
logging.getLogger("asyncio").addHandler(SLOW)


@pytest.fixture(autouse=True)
def test_guard(request, monkeypatch):
    block = request.node.get_closest_marker("allow_exec") is None
    for owner, name, value in guard.patches(block_programs=block):
        monkeypatch.setattr(owner, name, value)
    SLOW.messages.clear()
    yield
    if SLOW.messages:
        pytest.fail("event loop blocked: " + "; ".join(SLOW.messages[:3]))


@pytest.fixture
def data_dir():
    return DATA_DIR


@pytest.fixture
def paris():
    saved = os.environ.get("TZ")
    os.environ["TZ"] = "Europe/Paris"
    time.tzset()
    yield
    if saved is None:
        os.environ.pop("TZ", None)
    else:
        os.environ["TZ"] = saved
    time.tzset()
