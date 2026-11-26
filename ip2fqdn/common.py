import datetime
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass

CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
MASK_KINDS = {"ip": "ip", "server": "ip", "host": "host", "name": "host", "zone": "host",
              "path": "path", "text": "text", "url": "text", "value": "text"}


class UsageError(Exception):
    pass


class FatalError(Exception):
    pass


@dataclass(slots=True)
class Finding:
    ip: str
    name: str
    detail: str = ""
    first_seen: float | None = None
    last_seen: float | None = None


@dataclass(slots=True)
class Answer:
    ip: str
    findings: list


def sanitize(text):
    return CONTROL_CHARS.sub(_escape_control, text)


def _escape_control(match):
    return f"\\x{ord(match.group()):02x}"


def text_shape(text):
    parts = [f"len={len(text)}"]
    nonascii = sum(1 for char in text if ord(char) > 127)
    control = len(CONTROL_CHARS.findall(text))
    if nonascii:
        parts.append(f"nonascii={nonascii}")
    if control:
        parts.append(f"ctrl={control}")
    return " ".join(parts)


class Masker:
    def __init__(self, enabled):
        self.enabled = enabled
        self._seen = {}
        self._counts = Counter()

    def _placeholder(self, kind, value):
        key = (kind, value)
        if key not in self._seen:
            self._counts[kind] += 1
            self._seen[key] = f"{kind}-{self._counts[kind]}"
        return self._seen[key]

    def ip(self, value):
        if not self.enabled or not value:
            return value
        return self._placeholder("IP6" if ":" in value else "IP4", value)

    def host(self, value):
        if not self.enabled or not value:
            return value
        return self._placeholder("HOST", value)

    def path(self, value):
        if not self.enabled or not value:
            return value
        return self._placeholder("PATH", value) + os.path.splitext(value)[1]

    def text(self, value):
        if not self.enabled or not value:
            return value
        return f"{self._placeholder('TEXT', value)}[{text_shape(value)}]"

    def field(self, key, value):
        kind = MASK_KINDS.get(key)
        if kind is None or value is None:
            return value
        if isinstance(value, (list, tuple, set)):
            return ",".join(str(getattr(self, kind)(str(item))) for item in value)
        return getattr(self, kind)(str(value))


class Log:
    def __init__(self, stream=None, debug=False):
        self.stream = stream or sys.stderr
        self.debugging = debug
        self.masker = Masker(debug)
        self.tty = _isatty(self.stream)
        self._status_shown = False

    def enable_debug(self, enabled):
        self.debugging = enabled
        self.masker = Masker(enabled)

    def note(self, text):
        self._clear_status()
        self.stream.write(sanitize(text) + "\n")
        self.stream.flush()

    def warning(self, text):
        self.note(f"warning: {text}")

    def debug(self, event, **fields):
        if not self.debugging:
            return
        parts = [event] + [f"{key}={self.masker.field(key, value)}"
                           for key, value in fields.items() if value is not None]
        self._clear_status()
        self.stream.write("[debug] " + sanitize(" ".join(str(part) for part in parts)) + "\n")
        self.stream.flush()

    def status(self, text):
        if not self.tty:
            return
        self.stream.write("\r\x1b[K" + sanitize(text))
        self.stream.flush()
        self._status_shown = True

    def _clear_status(self):
        if self._status_shown:
            self.stream.write("\r\x1b[K")
            self._status_shown = False


def _isatty(stream):
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return False


def local_time(epoch):
    return datetime.datetime.fromtimestamp(epoch).astimezone()


def show_time(epoch):
    if epoch is None:
        return ""
    moment = local_time(epoch)
    offset = moment.strftime("%z")
    return moment.strftime("%Y-%m-%d %H:%M ") + offset[:3] + ":" + offset[3:]


def show_duration(seconds):
    seconds = round(seconds)
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h{minutes:02d}m"
    if minutes:
        return f"{minutes}m{secs:02d}s"
    return f"{secs}s"


def parse_date(text):
    if not isinstance(text, str) or not text:
        return None
    try:
        moment = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.UTC)
    return moment.timestamp()


USER_AGENT = "Mozilla/5.0 (compatible; ip2fqdn)"
