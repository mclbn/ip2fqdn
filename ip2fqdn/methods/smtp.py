import asyncio
import re

from ip2fqdn.common import Finding
from ip2fqdn.proto import certs, net

NAME = "smtp"
HELP = "SMTP greeting and EHLO names, STARTTLS certificate names"
KIND = "active"
PRESETS = ("default", "active", "cert")
PORTS = (25, 587)
PROTOCOL = "tcp"
NMAP_SERVICES = ("smtp", "submission")
RATE = 0
TIMEOUT = 20.0
PHASE = 1
PARALLEL = None
NEEDS = ""
MAX_LINES = 100
MAX_LINE = 4096
QUIT_WAIT = 2.0
REPLY_LINE = re.compile(rb"^([2-5][0-9][0-9])([ -]|$)(.*)$", re.DOTALL)


class OverLimit(Exception):
    pass


class Session:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.lines = 0

    async def reply(self):
        code = None
        lines = []
        while True:
            line = await self._line()
            match = REPLY_LINE.match(line)
            if not match or (code is not None and match[1] != code):
                return None, lines
            code = match[1]
            lines.append(match[3].decode("ascii", "replace"))
            if match[2] != b"-":
                return int(code), lines

    async def _line(self):
        self.lines += 1
        if self.lines > MAX_LINES:
            raise OverLimit()
        try:
            line = await self.reader.readuntil(b"\n")
        except asyncio.LimitOverrunError:
            raise OverLimit() from None
        except asyncio.IncompleteReadError as error:
            if not error.partial:
                raise
            line = error.partial
        if len(line) > MAX_LINE:
            raise OverLimit()
        return line.rstrip(b"\r\n")

    async def send(self, text):
        self.writer.write(text.encode("ascii") + b"\r\n")
        await self.writer.drain()

    async def quit(self):
        try:
            await self.send("QUIT")
            async with asyncio.timeout(QUIT_WAIT):
                await self.reply()
        except (OSError, TimeoutError, OverLimit, asyncio.IncompleteReadError):
            pass


def first_word(lines):
    if not lines or not lines[0].strip():
        return None
    word = lines[0].split()[0]
    if word.startswith("["):
        return None
    return word


def ehlo_argument(writer):
    local = writer.get_extra_info("sockname")
    address = local[0] if local else "127.0.0.1"
    return f"[IPv6:{address}]" if ":" in address else f"[{address}]"


async def lookup(ip, port, ctx):
    found = []
    try:
        async with net.connection(ip, port, ctx.connect_timeout, MAX_LINE) as (reader, writer):
            await _session(Session(reader, writer), ip, port, ctx, found)
    except OverLimit:
        ctx.warn_limited("sessions over the read limit",
                         f"{ip}:{port}: more than {MAX_LINES} lines or a line over 4 KB; "
                         "session ended")
    for finding in found:
        yield finding


async def _session(session, ip, port, ctx, found):
    code, lines = await session.reply()
    if code is None:
        return
    name = first_word(lines)
    if name:
        found.append(Finding(ip, name, f"{port} greeting"))
    if code != 220:
        await session.quit()
        return
    await session.send(f"EHLO {ehlo_argument(session.writer)}")
    code, lines = await session.reply()
    if code != 250:
        await session.quit()
        return
    name = first_word(lines)
    if name:
        found.append(Finding(ip, name, f"{port} EHLO"))
    if not any(line.split()[:1] and line.split()[0].upper() == "STARTTLS"
               for line in lines[1:]):
        await session.quit()
        return
    await session.send("STARTTLS")
    code, _ = await session.reply()
    if code != 220:
        await session.quit()
        return
    der = await net.start_tls(session.writer)
    found.extend(certs.findings(ip, der, f"{port} STARTTLS", ctx))
    await session.quit()
