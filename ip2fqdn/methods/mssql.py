import asyncio
import ssl
import struct

from ip2fqdn.proto import net, ntlm

NAME = "mssql"
HELP = "SQL Server (TDS) Windows-authentication login stopped at the NTLM challenge"
KIND = "active"
PRESETS = ("default", "active", "windows")  # SQL Server logs error 17830: see D63
PORTS = (1433,)
PROTOCOL = "tcp"
NMAP_SERVICES = ("ms-sql-s",)
RATE = 0
TIMEOUT = None
PHASE = 1
PARALLEL = None
NEEDS = ""
PRELOGIN = 0x12
TABULAR_RESULT = 0x04
LOGIN7 = 0x10
END_OF_MESSAGE = 0x01
ENCRYPT_OFF, ENCRYPT_ON, ENCRYPT_NOT_SUP, ENCRYPT_REQ = 0, 1, 2, 3
OPTION_VERSION, OPTION_ENCRYPTION, OPTION_INSTOPT, OPTION_THREADID = 0, 1, 2, 3
TERMINATOR = 0xFF
SSPI_TOKEN = 0xED
TDS_VERSION = 0x74000004  # TDS 7.4
LOGIN7_FIXED = 94
INTEGRATED_SECURITY = 0x80  # OptionFlags2 fIntSecurity
PACKET_DATA = 4096 - 8
MAX_MESSAGE = 64 * 1024


class TdsError(ValueError):
    pass


def packets(kind, payload):
    """[MS-TDS] 2.2.3.1: 8-byte header (type, status, big-endian length, SPID, packet ID,
    window); the last packet of a message carries the end-of-message status."""
    chunks = [payload[i:i + PACKET_DATA] for i in range(0, len(payload), PACKET_DATA)] or [b""]
    out = b""
    for number, chunk in enumerate(chunks, 1):
        status = END_OF_MESSAGE if number == len(chunks) else 0
        out += struct.pack(">BBHHBB", kind, status, 8 + len(chunk), 0, number & 0xFF, 0) + chunk
    return out


def prelogin(encryption):
    """[MS-TDS] 2.2.6.5 PRELOGIN: VERSION first, then ENCRYPTION, INSTOPT, THREADID."""
    options = [(OPTION_VERSION, bytes(6)), (OPTION_ENCRYPTION, bytes([encryption])),
               (OPTION_INSTOPT, b"\x00"), (OPTION_THREADID, bytes(4))]
    offset = 5 * len(options) + 1
    table, data = b"", b""
    for token, value in options:
        table += struct.pack(">BHH", token, offset + len(data), len(value))
        data += value
    return table + bytes([TERMINATOR]) + data


def prelogin_option(payload, wanted):
    position = 0
    while position < len(payload) and payload[position] != TERMINATOR:
        if position + 5 > len(payload):
            raise TdsError("truncated PRELOGIN option table")
        token, offset, length = struct.unpack_from(">BHH", payload, position)
        if token == wanted:
            if offset + length > len(payload):
                raise TdsError("PRELOGIN option beyond the message")
            return payload[offset:offset + length]
        position += 5
    return None


def login7():
    """[MS-TDS] 2.2.6.4 LOGIN7 with integrated security: no name, no password, only the NTLM
    negotiate message as SSPI data."""
    sspi = ntlm.NEGOTIATE
    head = struct.pack("<IIIIII", LOGIN7_FIXED + len(sspi), TDS_VERSION, 4096, 0, 0, 0)
    head += bytes([0, INTEGRATED_SECURITY, 0, 0]) + struct.pack("<iI", 0, 0x0409)
    empty = struct.pack("<HH", LOGIN7_FIXED, 0)
    offsets = empty * 9 + bytes(6) + struct.pack("<HH", LOGIN7_FIXED, len(sspi)) + empty * 2
    offsets += struct.pack("<I", 0)
    assert len(head + offsets) == LOGIN7_FIXED
    return head + offsets + sspi


def sspi_challenge(payload):
    """The NTLM challenge in the server's SSPI token ([MS-TDS] 2.2.7.22), or None."""
    if len(payload) < 3 or payload[0] != SSPI_TOKEN:
        return None
    (length,) = struct.unpack_from("<H", payload, 1)
    return ntlm.parse_challenge(payload[3:3 + length])


class Plain:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer

    async def send(self, data):
        self.writer.write(data)
        await self.writer.drain()

    async def receive(self, size):
        return await self.reader.readexactly(size)


class Encrypted:
    """TLS for TDS 7.x ([MS-TDS] 2.2.6.5): handshake records travel inside PRELOGIN packets,
    then every packet is a TLS record on the bare connection (full encryption)."""

    def __init__(self, plain):
        self.plain = plain
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        # TLS 1.3 comes with TDS 8 only; a 1.3 server would send tickets after the handshake,
        # whose framing TDS 7.x does not define.
        context = net.tls_context(ssl.TLSVersion.TLSv1_2)
        self.tls = context.wrap_bio(self.incoming, self.outgoing)
        self.buffer = b""

    async def _flush(self):
        data = self.outgoing.read()
        if data:
            await self.plain.send(packets(PRELOGIN, data))

    async def handshake(self):
        while True:
            try:
                self.tls.do_handshake()
                break
            except ssl.SSLWantReadError:
                await self._flush()
                kind, payload = await read_message(self.plain)
                if kind not in (PRELOGIN, TABULAR_RESULT):
                    raise TdsError("unexpected packet during the TLS handshake") from None
                self.incoming.write(payload)
        await self._flush()

    async def send(self, data):
        self.tls.write(data)
        await self.plain.send(self.outgoing.read())

    async def receive(self, size):
        while len(self.buffer) < size:
            try:
                self.buffer += self.tls.read(MAX_MESSAGE)
            except ssl.SSLWantReadError:
                chunk = await self.plain.reader.read(MAX_MESSAGE)
                if not chunk:
                    raise asyncio.IncompleteReadError(self.buffer, size) from None
                self.incoming.write(chunk)
        data, self.buffer = self.buffer[:size], self.buffer[size:]
        return data


async def read_message(channel):
    """(packet type, payload) of one message, its packets joined."""
    payload = b""
    while True:
        kind, status, length = struct.unpack(">BBH", await channel.receive(4))
        await channel.receive(4)
        if length < 8:
            raise TdsError("packet shorter than its header")
        if len(payload) + length > MAX_MESSAGE:
            raise TdsError(f"message over {MAX_MESSAGE} bytes")
        payload += await channel.receive(length - 8)
        if status & END_OF_MESSAGE:
            return kind, payload


async def _attempt(ip, port, ctx, encryption):
    """(server's encryption answer, parsed challenge or None) for one connection."""
    async with net.connection(ip, port, ctx.connect_timeout) as (reader, writer):
        channel = Plain(reader, writer)
        await channel.send(packets(PRELOGIN, prelogin(encryption)))
        kind, payload = await read_message(channel)
        answer = prelogin_option(payload, OPTION_ENCRYPTION) if kind == TABULAR_RESULT else None
        if not answer:
            raise TdsError("no PRELOGIN answer")
        answer = answer[0]
        if encryption == ENCRYPT_NOT_SUP and answer not in (ENCRYPT_NOT_SUP, ENCRYPT_OFF):
            return answer, None  # the server requires encryption and closes the connection
        if encryption == ENCRYPT_ON:
            if answer != ENCRYPT_ON:
                return answer, None
            channel = Encrypted(channel)
            await channel.handshake()
        await channel.send(packets(LOGIN7, login7()))
        kind, payload = await read_message(channel)
        return answer, sspi_challenge(payload) if kind == TABULAR_RESULT else None


async def lookup(ip, port, ctx):
    """No encryption first; TLS inside TDS only when the server requires it."""
    try:
        answer, parsed = await _attempt(ip, port, ctx, ENCRYPT_NOT_SUP)
        if parsed is None and answer in (ENCRYPT_REQ, ENCRYPT_ON):
            answer, parsed = await _attempt(ip, port, ctx, ENCRYPT_ON)
    except TdsError as error:
        ctx.count("unreadable replies")
        ctx.debug("unreadable reply", ip=ip, port=port, error=str(error))
        return
    if not parsed:
        ctx.debug("no NTLM challenge", ip=ip, port=port, encryption=answer)
        return
    for finding in ntlm.findings(ip, port, parsed, ctx):
        yield finding
