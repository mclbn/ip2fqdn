import csv
import io

from ip2fqdn.addresses import sort_key
from ip2fqdn.common import sanitize, show_time
from ip2fqdn.names import is_generic, is_placeholder, name_kind

COLUMNS = ("ip", "fqdn", "source", "detail", "name_kind", "labels", "dns", "sni", "first_seen",
           "last_seen")


def build_rows(run, shared):
    rows = []
    named_ips = set()
    for row in run.results.rows.values():
        named_ips.add(row.ip)
        rows.append(_csv_row(run, row, shared))
    for ip in run.inputs.ips:
        if ip not in named_ips:
            rows.append({"ip": ip})
    rows.sort(key=lambda item: (sort_key(item["ip"]), item.get("fqdn", ""),
                                item.get("source", "")))
    return rows


def _csv_row(run, row, shared):
    labels = []
    if is_generic(row.name, row.ip):
        labels.append("generic")
    if is_placeholder(row.name):
        labels.append("placeholder")
    if shared is not None and shared.contains(row.ip):
        labels.append("shared")
    return {"ip": row.ip, "fqdn": row.name, "source": row.source,
            "detail": "; ".join(row.details), "name_kind": name_kind(row.name),
            "labels": " ".join(labels), "dns": run.dns_status(row.ip, row.name),
            "sni": run.results.sni.get((row.ip, row.name), ""),
            "first_seen": show_time(row.first_seen), "last_seen": show_time(row.last_seen)}


def csv_text(rows):
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(COLUMNS)
    for row in rows:
        writer.writerow([sanitize(str(row.get(column, ""))) for column in COLUMNS])
    return buffer.getvalue()


def summary_lines(run, elapsed):
    lines = []
    for module in run.plan.methods:
        ctx = run.contexts[module.NAME]
        parts = [f"{len(ctx.ips)} IPs", f"{ctx.rows} rows", f"{ctx.timeouts} timeouts",
                 f"{ctx.errors} errors", f"{ctx.dropped} dropped names"]
        parts.extend(f"{key}: {value}" for key, value in sorted(ctx.counts.items()))
        if ctx.stopped:
            parts.append(ctx.stopped)
        lines.append(f"{module.NAME}: " + ", ".join(parts))
    return lines
