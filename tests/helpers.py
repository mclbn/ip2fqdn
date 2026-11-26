import asyncio
import io

from ip2fqdn import cli
from ip2fqdn.common import Log
from ip2fqdn.inputs import Inputs
from ip2fqdn.plan import build_plan
from ip2fqdn.runner import Run


def make_run(argv=(), ips=("127.0.1.1",), dns=None, log=None, nmap=None, environ=None):
    args = cli.build_parser().parse_args(["127.0.1.1", *argv])
    log = log or Log(io.StringIO())
    plan = build_plan(args, cli.METHODS, log, environ or {})
    inputs = Inputs(list(ips))
    if nmap is not None:
        inputs.nmap = nmap
    return Run(args, log, inputs, plan, dns)


def lookup(module, ip, port, argv=()):
    async def go():
        run = make_run(["-m", module.NAME, *argv], ips=(ip,))
        ctx = run.contexts[module.NAME]
        found = []
        async with asyncio.timeout(ctx.timeout):
            async for item in module.lookup(ip, port, ctx):
                found.append(item)
        return found, ctx
    return asyncio.run(go(), debug=True)


def run_cli(argv, environ=None, stdin=None):
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(list(argv), stdin=stdin, stdout=out, stderr=err, environ=environ or {})
    return code, out.getvalue(), err.getvalue()
