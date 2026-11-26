import asyncio
import time

from ip2fqdn.addresses import is_public
from ip2fqdn.apiclient import MethodOff, QuotaSpent
from ip2fqdn.context import Limits, MethodContext
from ip2fqdn.names import name_kind
from ip2fqdn.results import Results, confirm_eligible, sni_eligible

STATUS_EVERY = 3.0
DNS_RANK = {"match": 0, "other": 1, "none": 2, "error": 3}
SNI_DONE = object()


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
        self.zones = []
        self.confirm = dns is not None and not args.no_forward_confirm
        self.confirmations = {}
        self.background = set()
        self.sni_queue = asyncio.Queue()
        self.sni_live = False
        self.sni_seen = set()
        self.phase = 1
        self.started = time.time()

    async def execute(self):
        status = asyncio.create_task(self._status_loop())
        try:
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
        if found or self.log.debugging and time.monotonic() - started > ctx.connect_timeout:
            ctx.debug("lookup", ip=ip, port=port, names=found,
                      seconds=round(time.monotonic() - started, 2))

    async def _run_whole(self, module):
        ctx = self.contexts[module.NAME]
        ips = self.inputs.ips
        if module.KIND == "api":
            ips = self._api_ips(ctx)
        started = time.monotonic()
        ctx.debug("start", ips=len(ips), phase=module.PHASE)
        try:
            await self._consume(ctx, module, ips)
        finally:
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

    def _api_ips(self, ctx):
        public = [ip for ip in self.inputs.ips if is_public(ip)]
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
            module = self.plan.by_name[source]
            if source != "sni" and (module.PHASE == 1) and sni_eligible(name, ip):
                self._put_sni(ip, name)

    def _put_sni(self, ip, name):
        if (ip, name) in self.sni_seen or not self.results.tls_ports.get(ip):
            return
        self.sni_seen.add((ip, name))
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
        if not self.log.tty:
            return
        while True:
            await asyncio.sleep(STATUS_EVERY)
            elapsed = int(time.time() - self.started)
            self.log.status(f"ip2fqdn: phase {min(self.phase, 2)}, "
                            f"{len(self.results.names)} names, {elapsed} s")
