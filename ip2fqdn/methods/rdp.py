import asyncio
import struct

from ip2fqdn.proto import ber, certs, net, ntlm

NAME = "rdp"
HELP = "RDP negotiation on 3389, then TLS: certificate names; with NLA, first NTLM step"
KIND = "active"
PRESETS = ("default", "active", "windows", "cert")
PORTS = (3389,)
PROTOCOL = "tcp"
NMAP_SERVICES = ("ms-wbt-server",)
RATE = 0
TIMEOUT = None
PHASE = 1
PARALLEL = None
NEEDS = ""
CONNECTION_REQUEST = bytes.fromhex("030000130ee00000000000010008000b000000")
MAX_TPKT = 512
TLS_PROTOCOLS = (1, 2, 8)
NLA_PROTOCOLS = (2, 8)  # PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX: CredSSP follows TLS ([MS-RDPBCGR])
CREDSSP_VERSION = 6
MAX_TS_REQUEST = 64 * 1024


def selected_protocol(packet):
    if len(packet) < 11 or packet[0] != 3:
        return None
    length = struct.unpack_from(">H", packet, 2)[0]
    indicator = packet[4]
    if length != len(packet) or indicator + 5 > length or packet[5] & 0xF0 != 0xD0:
        return None
    if indicator < 14 or len(packet) < 19:
        return 0
    if packet[11] != 0x02:
        return None
    return struct.unpack_from("<I", packet, 15)[0]


async def read_tpkt(reader):
    head = await reader.readexactly(4)
    length = struct.unpack_from(">H", head, 2)[0]
    if head[0] != 3 or not 11 <= length <= MAX_TPKT:
        return None
    return head + await reader.readexactly(length - 4)


def ts_request():
    """[MS-CSSP] 2.2.1 TSRequest carrying the NTLM negotiate message in negoTokens."""
    token = ber.sequence(ber.encode(0xA0, ber.octets(ntlm.NEGOTIATE)))
    return ber.sequence(ber.encode(0xA0, ber.integer(CREDSSP_VERSION)),
                        ber.encode(0xA1, ber.sequence(token)))


def challenge_of(message):
    """The NTLM challenge in a TSRequest's first negoToken; None, with the error code if any."""
    tag, content, _ = ber.read(message)
    if tag != ber.SEQUENCE:
        raise ber.BerError("not a TSRequest")
    fields = dict(ber.children(content))
    if 0xA4 in fields:
        _, code, _ = ber.read(fields[0xA4])
        return None, ber.to_int(code) & 0xFFFFFFFF
    if 0xA1 not in fields:
        return None, None
    _, tokens, _ = ber.read(fields[0xA1])
    for _, item in ber.children(tokens):
        wrapped = dict(ber.children(item)).get(0xA0)
        if wrapped is not None:
            _, token, _ = ber.read(wrapped)
            return ntlm.parse_challenge(token), None
    return None, None


async def lookup(ip, port, ctx):
    parsed = None
    async with net.connection(ip, port, ctx.connect_timeout) as (reader, writer):
        writer.write(CONNECTION_REQUEST)
        await writer.drain()
        packet = await read_tpkt(reader)
        protocol = selected_protocol(packet) if packet else None
        if protocol not in TLS_PROTOCOLS:
            ctx.debug("no TLS offered", ip=ip, port=port, protocol=protocol)
            return
        der = await net.start_tls(writer)
        if protocol in NLA_PROTOCOLS:
            parsed = await _credssp_challenge(reader, writer, ip, port, ctx)
    for finding in certs.findings(ip, der, f"{port} RDP", ctx):
        yield finding
    if parsed:
        for finding in ntlm.findings(ip, port, parsed, ctx):
            yield finding


async def _credssp_challenge(reader, writer, ip, port, ctx):
    """First NTLM step only: the connection closes after the challenge, no credentials sent."""
    try:
        async with asyncio.timeout(ctx.connect_timeout):
            writer.write(ts_request())
            await writer.drain()
            parsed, code = challenge_of(await ber.read_element(reader, MAX_TS_REQUEST))
    except ber.BerError as error:
        ctx.count("unreadable replies")
        ctx.debug("unreadable CredSSP reply", ip=ip, port=port, error=str(error))
        return None
    except (TimeoutError, OSError, asyncio.IncompleteReadError) as error:
        ctx.debug("no CredSSP reply", ip=ip, port=port, error=type(error).__name__)
        return None
    if not parsed:
        ctx.debug("no NTLM challenge", ip=ip, port=port, error_code=code)
    return parsed
