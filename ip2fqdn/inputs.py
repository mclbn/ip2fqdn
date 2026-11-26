import ipaddress
import os
import sys
from dataclasses import dataclass, field

from ip2fqdn import nmapxml
from ip2fqdn.addresses import sort_key
from ip2fqdn.common import UsageError

SNIFF_BYTES = 4096
MAX_LIST_BYTES = 64 << 20
SHOWN_INVALID = 10
NMAP_MARKS = (b"<!DOCTYPE nmaprun", b"<nmaprun")


@dataclass
class Inputs:
    ips: list = field(default_factory=list)
    nmap: nmapxml.NmapData = field(default_factory=nmapxml.NmapData)


def parse_target(text):
    try:
        if "/" in text:
            return ipaddress.ip_network(text, strict=False)
        return ipaddress.ip_address(text)
    except ValueError:
        return None


class _Collector:
    def __init__(self, max_ips):
        self.max_ips = max_ips
        self.ips = {}

    def add(self, target):
        if isinstance(target, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            if target.num_addresses > self.max_ips:
                self._too_many()
            for address in _all_addresses(target):
                self._add_one(str(address))
        else:
            self._add_one(str(target))

    def _add_one(self, ip):
        self.ips[ip] = None
        if len(self.ips) > self.max_ips:
            self._too_many()

    def _too_many(self):
        raise UsageError(f"more than {self.max_ips} IPs to look up; raise the limit with "
                         "--max-ips N")


def _all_addresses(network):
    if network.num_addresses == 1:
        return [network.network_address]
    return iter(network)


def read_inputs(arguments, max_ips, log, stdin=None):
    collector = _Collector(max_ips)
    inputs = Inputs()
    for argument in arguments:
        target = parse_target(argument)
        if target is not None:
            collector.add(target)
        elif argument == "-":
            stream = stdin if stdin is not None else sys.stdin.buffer
            _read_list(stream, "stdin", collector, log)
        else:
            _read_file(argument, collector, inputs.nmap, log)
    if not collector.ips:
        raise UsageError("no IP to look up")
    inputs.ips = sorted(collector.ips, key=sort_key)
    return inputs


def _read_file(path, collector, nmap_data, log):
    if not os.path.exists(path):
        raise UsageError(f"{path}: not an IP or CIDR range, and no such file")
    try:
        with open(path, "rb") as handle:
            head = handle.read(SNIFF_BYTES)
            handle.seek(0)
            if any(mark in head for mark in NMAP_MARKS):
                _read_nmap(handle, path, collector, nmap_data, log)
                return
            if os.fstat(handle.fileno()).st_size > MAX_LIST_BYTES:
                raise UsageError(f"{path}: file over 64 MB that is not nmap or masscan XML")
            _read_list(handle, path, collector, log)
    except OSError as error:
        raise UsageError(f"{path}: cannot read: {error.strerror}") from None


def _read_nmap(handle, path, collector, nmap_data, log):
    nmap_file = nmapxml.read_xml(handle, path)
    if nmap_file.kind == "refused":
        raise UsageError(f"{path}: XML entity declarations refused")
    if nmap_file.kind == "not-nmap":
        raise UsageError(f"{path}: not nmap or masscan XML")
    for ip in nmap_file.hosts:
        collector.add(ipaddress.ip_address(ip))
    nmap_data.add(nmap_file)
    label = "nmap XML" if nmap_file.kind == "nmap" else "masscan XML"
    log.note(f"{path}: {label}, {len(nmap_file.hosts)} hosts")
    if nmap_file.problem:
        log.warning(f"{path}: damaged XML at line {nmap_file.problem['line']} "
                 f"({nmap_file.problem['message']}); complete hosts kept")


def _read_list(stream, label, collector, log):
    entries = invalid = 0
    for number, raw in enumerate(stream, 1):
        text = raw.decode("utf-8", "replace").split("#", 1)[0].strip()
        if not text:
            continue
        target = parse_target(text)
        if target is None:
            invalid += 1
            if invalid <= SHOWN_INVALID:
                log.warning(f"{label}:{number}: not an IP or CIDR range, ignored")
            continue
        entries += 1
        collector.add(target)
    if invalid > SHOWN_INVALID:
        log.warning(f"{label}: {invalid} invalid lines in all, ignored")
    log.note(f"{label}: IP list, {entries} entries")
