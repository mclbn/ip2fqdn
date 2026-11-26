import asyncio
import ssl
import time
from collections import Counter
from contextlib import asynccontextmanager

from ip2fqdn.common import Answer, Finding

QUIET_ERRORS = (OSError, ssl.SSLError, asyncio.IncompleteReadError, EOFError,
                asyncio.LimitOverrunError)
SHOWN_ERRORS = 5


class MethodContext:
    def __init__(self, module, run):
        self.module = module
        self.name = module.NAME
        self.run = run
        self.args = run.args
        self.log = run.log
        self.connect_timeout = run.args.connect_timeout
        self.timeout = _method_timeout(module, run.args)
        self.ips = set()
        self.rows = 0
        self.timeouts = 0
        self.errors = 0
        self.dropped = 0
        self.counts = Counter()
        self.stopped = None
        self.semaphore = asyncio.Semaphore(module.PARALLEL) if module.PARALLEL else None
        # Progress (D57): total units, units done when the method counts its own (counting),
        # otherwise the IPs done; running while the method works; time of the last unit done.
        self.total = None
        self.finished = 0
        self.counting = False
        self.running = False
        self.last_progress = None

    @property
    def nmap(self):
        return self.run.inputs.nmap

    @property
    def dns(self):
        return self.run.dns

    @property
    def zones(self):
        return self.run.zones

    def option(self, key):
        return getattr(self.args, f"{self.name.replace('-', '_')}_{key}", None)

    def debug(self, event, **fields):
        self.log.debug(f"{self.name} {event}", **fields)

    def warning(self, text):
        self.log.warning(f"{self.name}: {text}")

    def warn_limited(self, key, text):
        self.counts[key] += 1
        if self.counts[key] <= SHOWN_ERRORS:
            self.warning(text)

    def count(self, key, amount=1):
        self.counts[key] += amount

    def done(self, ip):
        if ip not in self.ips:
            self.ips.add(ip)
            self.last_progress = time.monotonic()

    def begin(self):
        if not self.running:
            self.running = True
            self.last_progress = time.monotonic()

    def set_total(self, total):
        self.counting = True
        self.total = total

    def advance(self, amount=1):
        self.finished += amount
        self.last_progress = time.monotonic()

    def progress(self):
        return self.finished if self.counting else len(self.ips)

    def learn_zones(self, names):
        for name in names:
            self.run.results.add_zone_candidate(name)

    def tls_answered(self, ip, port):
        self.run.results.tls_answered(ip, port)

    def nmap_tls(self, ip, port):
        return self.run.inputs.nmap.is_tls(ip, port)

    @asynccontextmanager
    async def slot(self, ip):
        async with self.run.limits.slot(ip):
            yield

    def set_sni(self, ip, name, status):
        self.run.set_sni(ip, name, status)

    async def request(self, url, ips, **options):
        return await self.run.api.request(self, url, ips, **options)

    def api_key(self):
        return self.run.api.key(self.module.KEY) if getattr(self.module, "KEY", None) else None

    def base_url(self):
        return self.run.api.base_url(self.name, self.module.BASE)

    def quota_spent(self, text):
        from ip2fqdn.apiclient import QuotaSpent
        return QuotaSpent(text)

    def switch_off(self, text):
        from ip2fqdn.apiclient import MethodOff
        return MethodOff(text)

    def failure(self, error, where=""):
        if isinstance(error, TimeoutError):
            self.timeouts += 1
            self.debug("timeout", ip=where or None)
            return
        if isinstance(error, QUIET_ERRORS):
            self.debug("no answer", error=type(error).__name__, ip=where or None)
            return
        self.errors += 1
        self.debug("error", error=type(error).__name__, ip=where or None)
        if self.errors <= SHOWN_ERRORS:
            self.warning(f"unexpected {type(error).__name__} ({error})")

    def add(self, item, via=None):
        if isinstance(item, Answer):
            self.run.answer(self, item)
            return
        if isinstance(item, Finding):
            self.run.finding(self, item, via)


def _method_timeout(module, args):
    specific = getattr(args, f"{module.NAME.replace('-', '_')}_timeout", None)
    if specific is not None:
        return specific
    if args.timeout is not None:
        return args.timeout
    return module.TIMEOUT or 10.0


class Limits:
    def __init__(self, parallel, per_ip=10):
        self.overall = asyncio.Semaphore(parallel)
        self.per_ip_limit = per_ip
        self.per_ip = {}

    @asynccontextmanager
    async def slot(self, ip):
        semaphore = self.per_ip.get(ip)
        if semaphore is None:
            semaphore = self.per_ip[ip] = asyncio.Semaphore(self.per_ip_limit)
        async with self.overall, semaphore:
            yield
