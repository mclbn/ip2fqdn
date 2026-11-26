import asyncio

from ip2fqdn.common import Finding
from ip2fqdn.proto import certs, net

NAME = "sni"
HELP = "for each name found, TLS with the name as SNI on the ports where tls answered"
KIND = "active"
PRESETS = ("default", "active", "cert")
PORTS = ()
PROTOCOL = "tcp"
NMAP_SERVICES = ()
RATE = 0
TIMEOUT = None
PHASE = 2
PARALLEL = None
NEEDS = ""
START_BATCH = 50


async def lookup_all(ips, ctx):
    results = asyncio.Queue()
    workers = []
    for _ in range(ctx.args.parallel):
        workers.append(asyncio.create_task(_worker(ctx, results)))
        if len(workers) % START_BATCH == 0:
            await asyncio.sleep(0)
    finished = 0
    try:
        while finished < len(workers):
            item = await results.get()
            if item is None:
                finished += 1
                continue
            yield item
    finally:
        for worker in workers:
            worker.cancel()


async def _worker(ctx, results):
    try:
        while (item := await ctx.run.sni_next()) is not None:
            ip, name, ports = item
            statuses = []
            for port in ports:
                statuses.append(await _check(ip, port, name, ctx, results))
            ctx.set_sni(ip, name, _combine(statuses))
            ctx.done(ip)
            ctx.advance()
    finally:
        results.put_nowait(None)


def _combine(statuses):
    if "served" in statuses:
        return "served"
    if "not-served" in statuses:
        return "not-served"
    return "error"


async def _check(ip, port, name, ctx, results):
    try:
        async with ctx.slot(ip), asyncio.timeout(ctx.timeout), \
                net.connection(ip, port, ctx.connect_timeout) as (_, writer):
            der = await net.start_tls(writer, server_hostname=name)
    except Exception as error:
        ctx.failure(error, ip)
        return "error"
    names = certs.der_names(der)
    if names is None:
        ctx.count("certificates unreadable")
        return "error"
    for other, where in names:
        if other.lower().rstrip(".") != name:
            results.put_nowait(Finding(ip, other, f"{port} SNI {name} {where}"))
    return "served" if certs.matches(names, name) else "not-served"
