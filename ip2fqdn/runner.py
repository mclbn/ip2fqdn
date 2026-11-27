import asyncio
import time
from collections import Counter
from types import SimpleNamespace

import dns.rdatatype

from ip2fqdn.addresses import is_public, sort_key
from ip2fqdn.apiclient import MethodOff, QuotaSpent
from ip2fqdn.common import Finding
from ip2fqdn.context import Limits, MethodContext
from ip2fqdn.dnsclient import ADDRESS_TYPES, note_public_servers
from ip2fqdn.inputs import SHOWN_INVALID, too_many
from ip2fqdn.names import name_kind
from ip2fqdn.results import Results, confirm_eligible, sni_eligible

STATUS_EVERY = 1.0
PROGRESS_EVERY = 60.0
STALL_AFTER = 10.0
DNS_RANK = {"match": 0, "other": 1, "none": 2, "error": 3}
SNI_DONE = object()
# Source of the rows for host names given as input (D55); not a method, so not selectable.
INPUT = SimpleNamespace(NAME="input", KIND="dns", PHASE=1, PARALLEL=None, TIMEOUT=None)
NOT_RESOLVED = "not resolved: --dns-server missing"


class Run:
    def __init__(self, args, log, inputs, plan, dns=None, api=None, cache=None):
        self.args = args
        self.log = log
        self.inputs = inputs
        self.plan = plan
        self.dns = dns
        self.api = api
        self.cache = cache
        self.results = Results(inputs.ips)
        self.limits = Limits(args.parallel)
        self.contexts = {module.NAME: MethodContext(module, self) for module in plan.methods}
        self.input_ctx = MethodContext(INPUT, self)
        if "sni" in self.contexts:
            self.contexts["sni"].set_total(0)
        self.name_counts = None
        self.no_address = {}  # input host name without address -> "none" or "error" (D55)
        self.final_warnings = []
        self.previous_rows = None
        self.zones = []
        self.confirm = dns is not None and not args.no_forward_confirm
        self.confirmations = {}
        self.background = set()
        self.sni_queue = asyncio.Queue()
        self.sni_live = False
        self.sni_seen = set()
        self.phase = 1
        self.started = time.monotonic()

    async def execute(self):
        status = asyncio.create_task(self._status_loop())
        try:
            await self.resolve_names()
            self._note_private()
            api_tasks = [self._spawn(self._run_whole(module)) for module in self.plan.methods
                         if module.KIND == "api"]
            await self._quick_phase()
            await self._learn_zones()
            self.phase = 2
            phase2 = [self._spawn(self._run_whole(module)) for module in self.plan.methods
                      if module.PHASE == 2]
            self._start_sni()
            await asyncio.gather(*api_tasks)
            self.sni_queue.put_nowait(SNI_DONE)
            await asyncio.gather(*phase2)
            self.phase = 3
            await self._drain_confirmations()
        finally:
            status.cancel()
            for task in list(self.background):
                task.cancel()

    async def resolve_names(self):
        for name in self.inputs.unresolved:
            self.results.add_row(Finding("", name, NOT_RESOLVED), INPUT.NAME, dated=False)
        names = self.inputs.names
        if not names or self.dns is None:
            return
        had_private = any(not is_public(ip) for ip in self.inputs.ips)
        self.input_ctx.set_total(len(names))
        self.input_ctx.begin()
        try:
            outcomes = await asyncio.gather(*(self._resolve_name(name) for name in names))
        finally:
            self.input_ctx.running = False
        results = [findings for findings, _ in outcomes]
        added = {finding.ip for findings in results for finding in findings}
        everything = set(self.inputs.ips) | added
        if len(everything) > self.args.max_ips:
            raise too_many(self.args.max_ips)
        self.inputs.ips = sorted(everything, key=sort_key)
        missing = [(name, origin) for (name, origin), findings in zip(names.items(), results)
                   if not findings]
        for name, origin in missing[:SHOWN_INVALID]:
            if origin is None:
                self.log.warning(f"{name}: no such file, and no address as a host name")
            else:
                self.log.warning(f"{origin}: {name}: no address")
        if len(missing) > SHOWN_INVALID:
            self.log.warning(f"{len(missing)} host names without address in all")
        self.name_counts = (len(names), len(added), len(missing))
        self.log.debug("input names resolved", names=len(names), addresses=len(added))
        if not had_private and any(not is_public(ip) for ip in added):
            note_public_servers(self.dns.servers, self.log)
        for findings in results:
            for finding in findings:
                self.input_ctx.add(finding)
        for name, (findings, failures) in zip(names, outcomes):
            if not findings:
                self._add_no_address(name, failures)

    async def _resolve_name(self, name):
        """Findings for the name's addresses, and (status, detail) for each answer without one."""
        findings, failures = [], []
        for server in self.dns.active():
            chains = await asyncio.gather(*(self.dns.chain(server, name, rdtype)
                                            for rdtype in ADDRESS_TYPES))
            for rdtype, (status, values, aliases) in zip(ADDRESS_TYPES, chains):
                rdtype_text = dns.rdatatype.to_text(rdtype)
                via = f", CNAME {' > '.join(aliases)}" if aliases else ""
                if status != "ok":
                    failures.append((status, f"{rdtype_text} {status} @{server.label()}{via}"))
                    continue
                record = f"{rdtype_text} @{server.label()}"
                for ip in sorted(values, key=sort_key):
                    findings.append(Finding(ip, name, record + via))
                    findings.extend(Finding(ip, alias, f"CNAME of {name}, {record}")
                                    for alias in aliases)
        self.input_ctx.advance()
        return findings, failures

    def _add_no_address(self, name, failures):
        """A row without IP keeps the name in the output (D55); dns column: none or error."""
        statuses = [status for status, _ in failures]
        all_none = bool(statuses) and all(status == "none" for status in statuses)
        self.no_address[name] = "none" if all_none else "error"
        for _, detail in failures or [(None, "")]:
            self.results.add_row(Finding("", name, detail), INPUT.NAME, dated=True)

    def _note_private(self):
        if self.api is None:
            return
        skipped = sum(1 for ip in self.inputs.ips if not is_public(ip))
        if skipped:
            self.log.note(f"third-party services: {skipped} non-public addresses skipped")

    def _spawn(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.background.add(task)
        task.add_done_callback(self.background.discard)
        return task

    async def _quick_phase(self):
        quick = [module for module in self.plan.methods
                 if module.PHASE == 1 and module.KIND != "api"]
        whole = [self._spawn(self._run_whole(module)) for module in quick
                 if hasattr(module, "lookup_all")]
        per_ip = [module for module in quick if hasattr(module, "lookup")]
        await self._run_lookups(per_ip)
        await asyncio.gather(*whole)

    async def _run_lookups(self, modules):
        if not modules:
            return
        totals = Counter(module.NAME for module, _, _ in self.plan.lookup_tasks(modules,
                                                                               self.inputs))
        for module in modules:
            self.contexts[module.NAME].set_total(totals[module.NAME])
        tasks = self.plan.lookup_tasks(modules, self.inputs)
        bound = self.plan.task_bound(modules, self.inputs)
        count = max(1, min(self.args.parallel, bound))
        workers = [asyncio.create_task(self._worker(tasks)) for _ in range(count)]
        try:
            await asyncio.gather(*workers)
        finally:
            for worker in workers:
                worker.cancel()

    async def _worker(self, tasks):
        for module, port, ip in tasks:
            ctx = self.contexts[module.NAME]
            if ctx.semaphore is not None:
                async with ctx.semaphore:
                    await self._lookup(ctx, module, ip, port)
            else:
                await self._lookup(ctx, module, ip, port)

    async def _lookup(self, ctx, module, ip, port):
        ctx.begin()
        ctx.done(ip)
        found = 0
        started = time.monotonic()
        async with self.limits.slot(ip):
            try:
                async with asyncio.timeout(ctx.timeout):
                    async for item in module.lookup(ip, port, ctx):
                        found += 1
                        ctx.add(item)
            except Exception as error:
                ctx.failure(error, ip)
        ctx.advance()
        if ctx.finished >= ctx.total:
            ctx.running = False
        if found or self.log.debugging and time.monotonic() - started > ctx.connect_timeout:
            ctx.debug("lookup", ip=ip, port=port, names=found,
                      seconds=round(time.monotonic() - started, 2))

    async def _run_whole(self, module):
        ctx = self.contexts[module.NAME]
        ips = self.inputs.ips
        total = len(ips)
        if module.KIND == "api":
            public = [ip for ip in ips if is_public(ip)]
            total = len(public)
            ips = self._api_ips(ctx, public)
        started = time.monotonic()
        ctx.debug("start", ips=len(ips), phase=module.PHASE)
        if not ctx.counting:
            ctx.total = total
        ctx.begin()
        try:
            await self._consume(ctx, module, ips)
        finally:
            ctx.running = False
            ctx.debug("end", rows=ctx.rows, seconds=round(time.monotonic() - started, 1))

    async def _consume(self, ctx, module, ips):
        try:
            async for item in module.lookup_all(ips, ctx):
                ctx.add(item)
        except QuotaSpent as error:
            ctx.stopped = "stopped: quota spent"
            self.log.note(f"{ctx.name}: quota spent ({error}); stopped for this run, the IPs "
                          "left can be looked up by running the same command later")
        except MethodOff as error:
            ctx.stopped = "switched off"
            self.log.warning(f"{ctx.name}: {error}; switched off for the run")
        except Exception as error:
            ctx.failure(error)

    def _api_ips(self, ctx, public):
        if self.cache is None:
            return public
        return self.cache.remaining(ctx, public)

    def finding(self, ctx, finding, via=None):
        added = self.results.add(finding, ctx.name, ctx.module.KIND in ("active", "dns"))
        if added is None:
            ctx.dropped += 1
            ctx.debug("name dropped", ip=finding.ip, text=finding.name)
            return
        name, new_row, new_pair = added
        ctx.done(finding.ip)
        if new_row:
            ctx.rows += 1
        if not new_pair:
            return
        quick = self.phase == 1 and ctx.module.KIND != "api"
        if quick:
            self.results.add_parent_candidate(name)
        if self.confirm and confirm_eligible(name):
            self._confirm(name)
        if ctx.name != "sni" and (quick or ctx.module.KIND == "api"):
            self._queue_sni(finding.ip, name)

    def answer(self, ctx, answer):
        ctx.done(answer.ip)
        if self.cache is not None:
            self.cache.record(ctx.name, answer)
        for finding in answer.findings:
            self.finding(ctx, finding)

    def _confirm(self, name):
        if name not in self.confirmations:
            self.confirmations[name] = self._spawn(self._confirm_name(name))

    async def _confirm_name(self, name):
        results = []
        for server in self.dns.active():
            results.append(await self.dns.addresses(server, name))
        return results

    async def _drain_confirmations(self):
        pending = [task for task in self.confirmations.values() if not task.done()]
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    def dns_status(self, ip, name):
        if not ip:
            return self.no_address.get(name, "")
        task = self.confirmations.get(name)
        if task is None or not task.done() or task.cancelled() or task.exception():
            return ""
        results = task.result()
        if not results:
            return ""
        if any(status == "ok" and ip in values for status, values in results):
            return "match"
        if any(status == "ok" for status, _ in results):
            return "other"
        if all(status == "none" for status, _ in results):
            return "none"
        return "error"

    def _queue_sni(self, ip, name):
        if "sni" not in self.contexts or not sni_eligible(name, ip):
            return
        if self.sni_live:
            self._put_sni(ip, name)

    def _start_sni(self):
        self.sni_live = True
        if "sni" not in self.contexts:
            return
        for (ip, name), source in list(self.results.names.items()):
            module = INPUT if source == INPUT.NAME else self.plan.by_name[source]
            if source != "sni" and (module.PHASE == 1) and sni_eligible(name, ip):
                self._put_sni(ip, name)

    def _put_sni(self, ip, name):
        if (ip, name) in self.sni_seen or not self.results.tls_ports.get(ip):
            return
        self.sni_seen.add((ip, name))
        self.contexts["sni"].set_total(len(self.sni_seen))
        self.sni_queue.put_nowait((ip, name, sorted(self.results.tls_ports[ip])))

    async def sni_next(self):
        item = await self.sni_queue.get()
        if item is SNI_DONE:
            self.sni_queue.put_nowait(SNI_DONE)
            return None
        return item

    def set_sni(self, ip, name, status):
        self.results.sni[(ip, name)] = status

    async def _learn_zones(self):
        wanted = any(module.NAME in ("axfr", "dns-enum") for module in self.plan.methods)
        if not wanted or self.dns is None:
            return
        zones = [(zone, True) for zone in self.plan.named_zones]
        seen = {zone for zone, _ in zones}
        for candidate in self.results.zone_candidates:
            if candidate in seen or name_kind(candidate) != "dotted":
                continue
            seen.add(candidate)
            if await self.dns.is_zone_apex(candidate):
                zones.append((candidate, False))
                self.log.debug("zone learned", zone=candidate)
        if len(zones) > self.args.max_zones:
            self.log.note(f"{len(zones) - self.args.max_zones} zones beyond --max-zones "
                          f"{self.args.max_zones} skipped")
            zones = zones[:self.args.max_zones]
        self.zones = zones

    async def _status_loop(self):
        """One redrawn line on a terminal, otherwise a plain line every minute (D57)."""
        tty = self.log.tty
        while True:
            await asyncio.sleep(STATUS_EVERY if tty else PROGRESS_EVERY)
            text = progress_text(self, time.monotonic())
            if tty:
                self.log.status(f"ip2fqdn {text}")
            else:
                self.log.note(f"progress {text}")


def progress_text(run, now):
    parts = [clock(now - run.started), f"{len(run.results.names)} names"]
    for ctx in (run.input_ctx, *run.contexts.values()):
        if not ctx.running:
            continue
        text = ctx.name if ctx.total is None else f"{ctx.name} {ctx.progress()}/{ctx.total}"
        if ctx.last_progress is not None and now - ctx.last_progress >= STALL_AFTER:
            text += f" (no progress for {int(now - ctx.last_progress)} s)"
        parts.append(text)
    checked = sum(1 for task in run.confirmations.values() if task.done())
    if checked < len(run.confirmations):
        parts.append(f"checks {checked}/{len(run.confirmations)}")
    return "  ".join(parts)


def clock(seconds):
    hours, rest = divmod(int(seconds), 3600)
    minutes, seconds = divmod(rest, 60)
    return f"{hours}:{minutes:02d}:{seconds:02d}" if hours else f"{minutes}:{seconds:02d}"
