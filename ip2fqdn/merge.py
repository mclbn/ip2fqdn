import csv
import datetime
import ipaddress

from ip2fqdn.common import UsageError
from ip2fqdn.output import COLUMNS, row_order

# Columns where the newer row wins unless its value is empty (D56).
NEWEST = ("name_kind", "labels", "dns", "sni")
DATE_FORMAT = "%Y-%m-%d %H:%M %z"


def read_existing(path):
    """Rows of an earlier ip2fqdn CSV, or None when the file does not exist."""
    try:
        with open(path, encoding="utf-8-sig", errors="replace", newline="") as handle:
            reader = csv.reader(handle)
            try:
                return _read_rows(reader, path)
            except csv.Error as error:
                raise UsageError(f"{path}:{reader.line_num}: unreadable CSV ({error}), "
                                 "not merged") from None
    except FileNotFoundError:
        return None
    except OSError as error:
        raise UsageError(f"{path}: cannot read: {error.strerror}, not merged") from None


def _read_rows(reader, path):
    header = next(reader, None)
    if header is None:
        return []
    if tuple(header) != COLUMNS:
        raise UsageError(f"{path}: not an ip2fqdn CSV (header differs), not merged")
    rows = []
    for values in reader:
        if not values:
            continue
        row = dict(zip(COLUMNS, values + [""] * (len(COLUMNS) - len(values))))
        try:
            if row["ip"] or not row["fqdn"]:  # a host name without address has no IP (D55)
                ipaddress.ip_address(row["ip"])
        except ValueError:
            raise UsageError(f"{path}:{reader.line_num}: not an IP in column ip, "
                             "not merged") from None
        rows.append(row)
    return rows


def merge_rows(old, new):
    merged = {}
    for row in [*old, *new]:
        row = {column: str(row.get(column, "")) for column in COLUMNS}
        key = (row["ip"], row["fqdn"], row["source"])
        kept = merged.get(key)
        merged[key] = row if kept is None else _combine(kept, row)
    named = {ip for ip, fqdn, _ in merged if fqdn}
    resolved = {fqdn for ip, fqdn, source in merged if ip and source == "input"}
    rows = [row for key, row in merged.items() if _kept(key, named, resolved)]
    rows.sort(key=row_order)
    return rows


def _kept(key, named, resolved):
    """An IP's row without name goes once the IP has a name; a host name's row without address
    goes once the name has an address (D56)."""
    ip, fqdn, source = key
    if not fqdn:
        return ip not in named
    return bool(ip) or source != "input" or fqdn not in resolved


def _combine(kept, row):
    result = dict(kept)
    for column in NEWEST:
        if row[column]:
            result[column] = row[column]
    places = [place for place in kept["detail"].split("; ") if place]
    places += [place for place in row["detail"].split("; ") if place and place not in places]
    result["detail"] = "; ".join(places)
    result["first_seen"] = _pick(kept["first_seen"], row["first_seen"], min)
    result["last_seen"] = _pick(kept["last_seen"], row["last_seen"], max)
    return result


def _pick(earlier, later, choose):
    """The date choose() prefers; a date that parses beats one that does not."""
    first, second = _parse(earlier), _parse(later)
    if first is not None and second is not None:
        return earlier if choose(first, second) == first else later
    if second is not None:
        return later
    if first is not None:
        return earlier
    return later or earlier


def _parse(text):
    try:
        return datetime.datetime.strptime(text, DATE_FORMAT)
    except ValueError:
        return None
