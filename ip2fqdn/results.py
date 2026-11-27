import time
from dataclasses import dataclass, field

from ip2fqdn.names import check_name, is_generic, is_placeholder, name_kind, parent_zone


@dataclass
class Row:
    ip: str
    name: str
    source: str
    details: list = field(default_factory=list)
    first_seen: float | None = None
    last_seen: float | None = None


class Results:
    def __init__(self, ips):
        self.ips = ips
        self.rows = {}
        self.names = {}
        self.dns = {}
        self.sni = {}
        self.zone_candidates = []
        self.tls_ports = {}

    def add(self, finding, source, dated):
        """Row and name found for the IP: (name, new row, new IP and name pair), None if dropped."""
        added = self.add_row(finding, source, dated)
        if added is None:
            return None
        name, new_row = added
        new_pair = (finding.ip, name) not in self.names
        if new_pair:
            self.names[(finding.ip, name)] = source
        return name, new_row, new_pair

    def add_row(self, finding, source, dated):
        """Row only, e.g. for a host name without address (D55): (name, new row), None if dropped."""
        name = check_name(finding.name)
        if name is None:
            return None
        first, last = finding.first_seen, finding.last_seen
        if first is None and last is None and dated:
            first = last = time.time()
        elif first is None or last is None:
            first = last = first if first is not None else last
        key = (finding.ip, name, source)
        row = self.rows.get(key)
        new_row = row is None
        if new_row:
            row = self.rows[key] = Row(finding.ip, name, source)
        if finding.detail and finding.detail not in row.details:
            row.details.append(finding.detail)
        _merge_dates(row, first, last)
        return name, new_row

    def add_zone_candidate(self, name):
        checked = check_name(name)
        if checked and "." in checked and checked not in self.zone_candidates:
            self.zone_candidates.append(checked)

    def add_parent_candidate(self, name):
        parent = parent_zone(name)
        if parent and parent not in self.zone_candidates:
            self.zone_candidates.append(parent)

    def tls_answered(self, ip, port):
        self.tls_ports.setdefault(ip, set()).add(port)


def _merge_dates(row, first, last):
    if first is not None and (row.first_seen is None or first < row.first_seen):
        row.first_seen = first
    if last is not None and (row.last_seen is None or last > row.last_seen):
        row.last_seen = last


def sni_eligible(name, ip):
    return (name_kind(name) == "dotted" and not is_generic(name, ip)
            and not is_placeholder(name))


def confirm_eligible(name):
    return name_kind(name) == "dotted"
