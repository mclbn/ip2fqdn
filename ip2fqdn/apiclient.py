import asyncio
import email.utils
import http.client
import json
import os
import time
import urllib.parse

from ip2fqdn.addresses import is_public
from ip2fqdn.common import USER_AGENT

CONNECT_TIMEOUT = 10
READ_TIMEOUT = 30
MAX_BODY = 32 << 20
DEFAULT_WAITS = (5, 10, 20)
QUOTA_WAIT = 3600
FAILURES_TO_STOP = 5
RETRY_STATUSES = range(500, 600)


class QuotaSpent(Exception):
    pass


class MethodOff(Exception):
    pass


class RequestFailed(Exception):
    pass


class Response:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body

    def header(self, name):
        return self.headers.get(name.lower())

    def json(self):
        try:
            return json.loads(self.body)
        except (ValueError, UnicodeDecodeError):
            return None


class _Pacer:
    def __init__(self, delay):
        self.delay = delay
        self.next_time = 0.0
        self.lock = asyncio.Lock()

    async def wait(self):
        async with self.lock:
            now = time.monotonic()
            if now < self.next_time:
                await asyncio.sleep(self.next_time - now)
            self.next_time = time.monotonic() + self.delay


class ApiClient:
    def __init__(self, log, environ=None):
        self.log = log
        self.environ = os.environ if environ is None else environ
        self.pacers = {}
        self.failures = {}

    def key(self, name):
        return self.environ.get(name) or None

    def base_url(self, method, default):
        variable = f"IP2FQDN_{method.upper().replace('-', '_')}_URL"
        return (self.environ.get(variable) or default).rstrip("/")

    def _pacer(self, ctx):
        pacer = self.pacers.get(ctx.name)
        if pacer is None:
            pace = getattr(ctx.module, "pace", None)
            delay = pace(self.key(ctx.module.KEY)) if pace else ctx.module.RATE
            pacer = self.pacers[ctx.name] = _Pacer(delay)
        return pacer

    async def request(self, ctx, url, ips, method="GET", headers=None, body=None, params=None,
                      waits=DEFAULT_WAITS, quota_after_waits=False):
        refused = [ip for ip in ips if not is_public(ip)]
        if refused or not ips:
            raise RuntimeError("request refused: non-public address")
        if params:
            url += "?" + urllib.parse.urlencode(params, safe=":,")
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json", **(headers or {})}
        response = None
        for attempt in range(len(waits) + 1):
            await self._pacer(ctx).wait()
            response = await self._send(ctx, url, method, headers, body)
            if response is None:
                break
            if response.status != 429 and response.status not in RETRY_STATUSES:
                self.failures[ctx.name] = 0
                return response
            if attempt == len(waits):
                break
            await self._wait(ctx, response, waits[attempt])
        return self._failed(ctx, response, quota_after_waits)

    async def _send(self, ctx, url, method, headers, body):
        started = time.monotonic()
        try:
            response = await asyncio.to_thread(_send_blocking, url, method, headers, body)
        except (OSError, http.client.HTTPException, ValueError) as error:
            ctx.debug("request failed", error=type(error).__name__, url=url)
            return None
        ctx.debug("request", status=response.status, bytes=len(response.body),
                  seconds=round(time.monotonic() - started, 2), url=url)
        if len(response.body) > MAX_BODY:
            ctx.warning("response over 32 MB dropped")
            return None
        return response

    async def _wait(self, ctx, response, default):
        seconds = _wait_seconds(response)
        if seconds is not None and seconds > QUOTA_WAIT:
            raise QuotaSpent(f"asked to wait {int(seconds)} s")
        if response.status == 429 and getattr(ctx.module, "RATE_BACKOFF", False):
            self._pacer(ctx).delay *= 2
        await asyncio.sleep(seconds if seconds is not None else default)

    def _failed(self, ctx, response, quota_after_waits):
        if response is not None and response.status == 429 and quota_after_waits:
            raise QuotaSpent("HTTP 429 after waiting")
        count = self.failures.get(ctx.name, 0) + 1
        self.failures[ctx.name] = count
        if count >= FAILURES_TO_STOP:
            raise MethodOff(f"{FAILURES_TO_STOP} requests in a row failed")
        status = response.status if response is not None else "no answer"
        raise RequestFailed(f"request failed ({status})")


def _wait_seconds(response):
    for name in ("retry-after", "x-rate-limit-reset-after"):
        value = response.header(name)
        if not value:
            continue
        try:
            return max(0.0, float(value))
        except ValueError:
            pass
        try:
            moment = email.utils.parsedate_to_datetime(value)
            return max(0.0, moment.timestamp() - time.time())
        except (TypeError, ValueError):
            continue
    return None


def _send_blocking(url, method, headers, body):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https":
        connection = http.client.HTTPSConnection(parts.hostname, parts.port,
                                                 timeout=CONNECT_TIMEOUT)
    elif parts.scheme == "http":
        connection = http.client.HTTPConnection(parts.hostname, parts.port,
                                                timeout=CONNECT_TIMEOUT)
    else:
        raise ValueError("unsupported URL scheme")
    try:
        connection.connect()
        connection.sock.settimeout(READ_TIMEOUT)
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query
        connection.request(method, target, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read(MAX_BODY + 1)
        found = {}
        for name, value in response.getheaders():
            found.setdefault(name.lower(), value)
        return Response(response.status, found, data)
    finally:
        connection.close()
