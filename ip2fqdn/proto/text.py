"""Line-based sessions (SMTP, IMAP, POP3, FTP): read limits, replies, STARTTLS, first NTLM step."""
import asyncio
import base64
import binascii
import re

from ip2fqdn.proto import certs, net, ntlm

MAX_LINES = 100
MAX_LINE = 4096
QUIT_WAIT = 2.0
NUMERIC_LINE = re.compile(rb"^([1-5][0-9][0-9])([ -]|$)(.*)$", re.DOTALL)
NTLM_TOKEN = base64.b64encode(ntlm.NEGOTIATE).decode("ascii")


class OverLimit(Exception):
    pass


class Session:
    def __init__(self, reader, writer, ip, port, ctx):
        self.reader = reader
        self.writer = writer
        self.ip = ip
        self.port = port
        self.ctx = ctx
        self.lines = 0
        self.found = []

    async def line(self):
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

    async def text_line(self):
        return (await self.line()).decode("ascii", "replace")

    async def send(self, text):
        self.writer.write(text.encode("ascii") + b"\r\n")
        await self.writer.drain()

    async def numeric_reply(self, free_lines=False):
        """(code, text of each line) of an SMTP or FTP reply; (None, lines) if malformed.

        SMTP (RFC 5321 section 4.2.1) starts every line with the code. FTP (RFC 959 section
        4.2) lets the lines between the first and the last hold any text: free_lines skips them.
        """
        code = None
        texts = []
        while True:
            match = NUMERIC_LINE.match(await self.line())
            if not match or (code is not None and match[1] != code):
                if free_lines and code is not None:
                    continue
                return None, texts
            code = match[1]
            texts.append(match[3].decode("ascii", "replace"))
            if match[2] != b"-":
                return int(code), texts

    async def start_tls(self, label):
        """TLS on the open connection; certificate names become rows (LABEL CN, LABEL SAN)."""
        der = await net.start_tls(self.writer)
        self.found.extend(certs.findings(self.ip, der, f"{self.port} {label}", self.ctx))

    async def later(self, step):
        """A step after the first finds, bounded by the connect timeout: a server that stops
        answering keeps what the session already found."""
        try:
            async with asyncio.timeout(self.ctx.connect_timeout):
                await step()
        except (TimeoutError, OSError, asyncio.IncompleteReadError) as error:
            self.ctx.debug("no reply to a later step", ip=self.ip, port=self.port,
                           error=type(error).__name__)

    def add_challenge(self, text):
        """Rows and zones from a base64 NTLM challenge; True when one was found."""
        token = text.strip()
        if not token or len(token) > ntlm.MAX_TOKEN * 4 // 3 + 4:
            return False
        try:
            parsed = ntlm.parse_challenge(base64.b64decode(token, validate=True))
        except (binascii.Error, ValueError):
            parsed = None
        if not parsed:
            self.ctx.debug("no NTLM challenge", ip=self.ip, port=self.port)
            return False
        self.found.extend(ntlm.findings(self.ip, str(self.port), parsed, self.ctx))
        return True

    async def goodbye(self, command, read_reply):
        try:
            await self.send(command)
            async with asyncio.timeout(QUIT_WAIT):
                await read_reply()
        except (OSError, TimeoutError, OverLimit, asyncio.IncompleteReadError):
            pass


async def converse(ip, port, ctx, talk, implicit_tls=False):
    """Findings of talk(session); a session cut short keeps what it found before."""
    session = None
    try:
        async with net.connection(ip, port, ctx.connect_timeout, MAX_LINE) as (reader, writer):
            session = Session(reader, writer, ip, port, ctx)
            if implicit_tls:
                await net.start_tls(writer)
            await talk(session)
    except OverLimit:
        ctx.warn_limited("sessions over the read limit",
                         f"{ip}:{port}: more than {MAX_LINES} lines or a line over 4 KB; "
                         "session ended")
    except (OSError, asyncio.IncompleteReadError) as error:
        if session is None or not session.found:
            raise
        ctx.debug("session ended early", ip=ip, port=port, error=type(error).__name__)
    return session.found if session else []


def greeting_word(text):
    """First word of a line, or None (SMTP: RFC 5321 section 4.3.1 puts the host name there)."""
    words = text.split()
    if not words or words[0].startswith("["):
        return None
    return words[0]


def ehlo_argument(writer):
    local = writer.get_extra_info("sockname")
    address = local[0] if local else "127.0.0.1"
    return f"[IPv6:{address}]" if ":" in address else f"[{address}]"


def offers_ntlm(lines, keyword):
    """True when a capability line lists NTLM after keyword: SMTP "AUTH NTLM LOGIN" (RFC 4954;
    "AUTH=" in old servers), POP3 "SASL NTLM PLAIN" (RFC 2449)."""
    for line in lines:
        words = line.upper().replace("=", " ").split()
        if words[:1] == [keyword] and "NTLM" in words[1:]:
            return True
    return False
