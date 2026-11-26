import json
import os
import time

from ip2fqdn.common import Finding, show_time

FORMAT = "ip2fqdn-api-cache"
VERSION = 1


class ApiCache:
    def __init__(self, path, log):
        self.path = path
        self.log = log
        self.entries = {}
        self.usable = True
        self.handle = None
        self.used = 0
        self.oldest = None

    def load(self):
        try:
            with open(self.path, encoding="utf-8", errors="replace") as handle:
                header = handle.readline()
                if not header:
                    return
                if not _valid_header(header):
                    self.usable = False
                    self.log.warning(f"{self.path}: not an ip2fqdn API cache, not used")
                    return
                for line in handle:
                    self._load_line(line)
        except FileNotFoundError:
            return
        except OSError as error:
            self.usable = False
            self.log.warning(f"{self.path}: cannot read ({error.strerror}), not used")

    def _load_line(self, line):
        try:
            entry = json.loads(line)
            key = (entry["service"], entry["ip"])
            date = float(entry["date"])
            findings = [Finding(entry["ip"], str(name), str(detail), _date(first),
                                _date(last))
                        for name, detail, first, last in entry["findings"]]
        except (ValueError, KeyError, TypeError):
            return
        self.entries[key] = (date, findings)

    def remaining(self, ctx, ips):
        if not self.usable:
            return ips
        left = []
        for ip in ips:
            cached = self.entries.get((ctx.name, ip))
            if cached is None:
                left.append(ip)
                continue
            date, findings = cached
            self.used += 1
            self.oldest = date if self.oldest is None else min(self.oldest, date)
            ctx.done(ip)
            for finding in findings:
                ctx.run.finding(ctx, finding)
        return left

    def record(self, service, answer):
        if not self.usable:
            return
        if self.handle is None:
            self._open()
        if self.handle is None:
            return
        entry = {"service": service, "ip": answer.ip, "date": time.time(),
                 "findings": [[f.name, f.detail, f.first_seen, f.last_seen]
                              for f in answer.findings]}
        self.handle.write(json.dumps(entry, ensure_ascii=True) + "\n")
        self.handle.flush()

    def _open(self):
        try:
            new = not os.path.exists(self.path) or os.path.getsize(self.path) == 0
            self.handle = open(self.path, "a", encoding="utf-8")  # noqa: SIM115
            if new:
                self.handle.write(json.dumps({"format": FORMAT, "version": VERSION}) + "\n")
        except OSError as error:
            self.usable = False
            self.log.warning(f"{self.path}: cannot write ({error.strerror}); no API cache")

    def close(self):
        if self.handle is not None:
            self.handle.close()
            self.handle = None

    def summary(self):
        if self.used:
            self.log.note(f"API cache: {self.used} cached answers used, oldest from "
                          f"{show_time(self.oldest)}")


def _valid_header(line):
    try:
        header = json.loads(line)
    except ValueError:
        return False
    return isinstance(header, dict) and header.get("format") == FORMAT and \
        header.get("version") == VERSION


def _date(value):
    return float(value) if isinstance(value, (int, float)) else None
