import argparse
import asyncio
import logging
import os
import resource
import signal
import sys
import time

from ip2fqdn import VERSION, dnsclient, ranges
from ip2fqdn.addresses import is_public
from ip2fqdn.apicache import ApiCache
from ip2fqdn.apiclient import ApiClient
from ip2fqdn.common import FatalError, Log, UsageError, show_duration
from ip2fqdn.inputs import read_inputs
from ip2fqdn.methods import METHODS
from ip2fqdn.output import build_rows, csv_text, summary_lines
from ip2fqdn.plan import PRESETS, build_plan
from ip2fqdn.runner import Run

DESCRIPTION = ("Find the FQDNs of a list of IP addresses. INPUT: IP, CIDR range, IP list file, "
               "- (stdin), nmap or masscan XML file.")
DNS_METHODS = ("ptr", "axfr", "dns-enum")
EXIT_SIGNALS = {signal.SIGINT: 130, signal.SIGTERM: 143}
FILE_MARGIN = 100
FILES_PER_SERVER = 50


def positive_int(text):
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be 1 or more: {text}")
    return value


def positive_float(text):
    value = float(text)
    if not value > 0:
        raise argparse.ArgumentTypeError(f"must be more than 0: {text}")
    return value


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise UsageError(message)


def build_parser(methods=METHODS):
    parser = _Parser(prog="ip2fqdn", description=DESCRIPTION)
    parser.add_argument("inputs", nargs="*", metavar="INPUT")
    parser.add_argument("-m", "--methods", default="default", metavar="LIST",
                        help="methods and presets to run (default: the default preset)")
    parser.add_argument("--skip", metavar="LIST", help="methods and presets to leave out")
    parser.add_argument("-o", "--output", metavar="FILE", help="CSV file (default: stdout)")
    parser.add_argument("--dns-server", metavar="IP[:PORT][,...]",
                        help="DNS servers to query (default: /etc/resolv.conf)")
    parser.add_argument("--protected-dns", action="store_true",
                        help="DNS queries only to --dns-server servers, for every input")
    parser.add_argument("--zones", metavar="LIST", help="zones for axfr and dns-enum")
    parser.add_argument("--no-forward-confirm", action="store_true",
                        help="no forward confirmation of the names found")
    parser.add_argument("--parallel", type=positive_int, default=500, metavar="N",
                        help="connections at once (default 500)")
    parser.add_argument("--connect-timeout", type=positive_float, default=3.0, metavar="S",
                        help="TCP connect or UDP reply timeout (default 3)")
    parser.add_argument("--timeout", type=positive_float, metavar="S",
                        help="time per method, IP and port (default 10, smtp 20)")
    parser.add_argument("--max-ips", type=positive_int, default=65536, metavar="N",
                        help="largest number of IPs accepted (default 65536)")
    parser.add_argument("--max-zones", type=positive_int, default=500, metavar="N",
                        help="largest number of zones for axfr and dns-enum (default 500)")
    parser.add_argument("--debug", action="store_true",
                        help="masked technical log on stderr, safe to share")
    parser.add_argument("--list-methods", action="store_true", help="list methods and exit")
    parser.add_argument("--version", action="version", version=f"ip2fqdn {VERSION}")
    for module in methods:
        _add_module_options(parser, module)
    return parser


def _add_module_options(parser, module):
    group = parser.add_argument_group(f"{module.NAME}", module.HELP)
    group.add_argument(f"--{module.NAME}-timeout", type=positive_float, metavar="S",
                       help="time per IP and port for this method")
    if module.PORTS or getattr(module, "HAS_PORTS", False):
        default = ",".join(str(port) for port in module.PORTS)
        group.add_argument(f"--{module.NAME}-ports", metavar="LIST",
                           help=f"ports, 'default' for the defaults ({default})")
    if hasattr(module, "add_arguments"):
        module.add_arguments(group)


def list_methods(methods, stream):
    for module in methods:
        state = "on" if "default" in module.PRESETS else "off"
        needs = getattr(module, "NEEDS", "") or "-"
        ports = ",".join(str(port) for port in module.PORTS) or "-"
        presets = ",".join(module.PRESETS) or "-"
        stream.write(f"{module.NAME:<11} {state:<3} {module.KIND:<6} phase {module.PHASE}  "
                     f"presets {presets}  needs {needs}  ports {ports}"
                     f"{'/udp' if module.PROTOCOL == 'udp' and module.PORTS else ''}\n")
    stream.write("presets: " + ", ".join(PRESETS) + "\n")


def run_command():
    code = main()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)


def main(argv=None, stdin=None, stdout=None, stderr=None, environ=None):
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    _quiet_asyncio_log()
    log = Log(stderr)
    try:
        return _main(argv, stdin, stdout, log, environ)
    except UsageError as error:
        log.note(f"error: {error}")
        return 2
    except FatalError as error:
        log.note(f"error: {error}")
        return 1


def _quiet_asyncio_log():
    logger = logging.getLogger("asyncio")
    if not any(isinstance(handler, logging.NullHandler) for handler in logger.handlers):
        logger.addHandler(logging.NullHandler())
    logger.propagate = False


def _main(argv, stdin, stdout, log, environ):
    args = build_parser().parse_args(argv)
    log.enable_debug(args.debug)
    if args.list_methods:
        list_methods(METHODS, stdout)
        return 0
    if not args.inputs:
        raise UsageError("no input given (see -h)")
    started = time.time()
    log.debug("start", version=VERSION, python=sys.version.split()[0])
    plan = build_plan(args, METHODS, log, environ)
    inputs = read_inputs(args.inputs, args.max_ips, log, stdin)
    dns = _dns_setup(args, inputs, plan, log)
    _raise_file_limit(args, dns, log)
    cache = _cache_setup(args, plan, log)
    api = ApiClient(log, environ) if any(m.KIND == "api" for m in plan.methods) else None
    if api is not None:
        _note_private(inputs, log)
    run = Run(args, log, inputs, plan, dns, api, cache)
    shared = _shared_ranges(log)
    code = asyncio.run(_execute(run, args, stdout, log, shared, started))
    return code


def _dns_setup(args, inputs, plan, log):
    named = dnsclient.parse_servers(args.dns_server) if args.dns_server else []
    resolv = dnsclient.resolv_conf_servers()
    has_private = any(not is_public(ip) for ip in inputs.ips)
    servers, protected = dnsclient.choose_servers(named, resolv, has_private,
                                                  args.protected_dns, log)
    if not servers:
        _drop_dns_methods(plan, protected, resolv, has_private, log)
        return None
    log.debug("dns servers", count=len(servers), protected=protected)
    return dnsclient.DnsService(servers, log)


def _drop_dns_methods(plan, protected, resolv, has_private, log):
    dropped = [module.NAME for module in plan.methods if module.NAME in DNS_METHODS]
    plan.methods = [module for module in plan.methods if module.NAME not in DNS_METHODS]
    skipped = ", ".join(dropped + ["forward confirmation"])
    if protected:
        reason = "internal addresses in the input" if has_private else "--protected-dns"
        listed = ", ".join(server.ip for server in resolv)
        hint = f" (resolv.conf lists {listed})" if listed else ""
        log.note(f"{reason}: DNS methods and checks need the client's DNS servers; add "
                 f"--dns-server{hint}; skipped: {skipped}")
    else:
        log.note(f"no DNS server (none given, none in /etc/resolv.conf); skipped: {skipped}")


def _raise_file_limit(args, dns, log):
    servers = len(dns.servers) if dns else 0
    wanted = args.parallel + FILES_PER_SERVER * servers + FILE_MARGIN
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft >= wanted:
        return
    target = wanted if hard == resource.RLIM_INFINITY else min(wanted, hard)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except (ValueError, OSError):
        target = soft
    if target < wanted:
        lowered = max(1, target - FILES_PER_SERVER * servers - FILE_MARGIN)
        log.note(f"open-file limit {target}: --parallel lowered from {args.parallel} to "
                 f"{lowered}")
        args.parallel = lowered


def _cache_setup(args, plan, log):
    if not args.output or not any(module.KIND == "api" for module in plan.methods):
        return None
    cache = ApiCache(args.output + ".api-cache", log)
    cache.load()
    return cache


def _note_private(inputs, log):
    skipped = sum(1 for ip in inputs.ips if not is_public(ip))
    if skipped:
        log.note(f"third-party services: {skipped} non-public addresses skipped")


def _shared_ranges(log):
    shared = ranges.load()
    if shared is None:
        log.note("shared ranges file missing (run setup.sh): no 'shared' label")
    return shared


async def _execute(run, args, stdout, log, shared, started):
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    received = []

    def on_signal(signum):
        if received:
            os._exit(EXIT_SIGNALS[signum])
        received.append(signum)
        task.cancel()

    for signum in EXIT_SIGNALS:
        loop.add_signal_handler(signum, on_signal, signum)
    try:
        await run.execute()
    except asyncio.CancelledError:
        if not received:
            raise
        task.uncancel()
    finally:
        for signum in EXIT_SIGNALS:
            loop.remove_signal_handler(signum)
    await asyncio.to_thread(_finish, run, args, stdout, log, shared, started, bool(received))
    return EXIT_SIGNALS[received[0]] if received else 0


def _finish(run, args, stdout, log, shared, started, interrupted):
    if run.cache is not None:
        run.cache.close()
    _write_output(run, args, stdout, log, shared)
    if interrupted:
        log.note("interrupted: results incomplete")
    _write_summary(run, args, log, started)


def _write_output(run, args, stdout, log, shared):
    text = csv_text(build_rows(run, shared))
    if not args.output:
        stdout.write(text)
        stdout.flush()
        return
    try:
        with open(args.output, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
    except OSError as error:
        raise FatalError(f"cannot write {args.output}: {error.strerror}") from None


def _write_summary(run, args, log, started):
    for line in summary_lines(run, time.time() - started):
        log.note(line)
    if run.cache is not None:
        run.cache.summary()
    where = args.output or "stdout"
    log.note(f"total time {show_duration(time.time() - started)}; output: {where}")
    log.debug("end", seconds=round(time.time() - started, 1),
              dns_queries=run.dns.queries if run.dns else 0)
