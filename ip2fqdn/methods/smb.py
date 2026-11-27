import os
import struct

from ip2fqdn.proto import net, ntlm

NAME = "smb"
HELP = "SMB2 negotiate and first NTLM step on 445: DNS and NetBIOS computer names"
KIND = "active"
PRESETS = ("default", "active", "windows")
PORTS = (445,)
PROTOCOL = "tcp"
NMAP_SERVICES = ("microsoft-ds",)
RATE = 0
TIMEOUT = None
PHASE = 1
PARALLEL = None
NEEDS = ""
MAX_FRAME = 64 * 1024
MAX_PENDING = 5
STATUS_PENDING = 0x00000103
STATUS_MORE_PROCESSING = 0xC0000016
DIALECTS = (0x0202, 0x0210, 0x0300, 0x0302, 0x0311)


def header(command, message_id):
    return struct.pack("<4sHHIHHIIQIIQ16s", b"\xfeSMB", 64, 0, 0, command, 1, 0, 0,
                       message_id, 0, 0, 0, b"\x00" * 16)


def negotiate_request(guid=None, salt=None):
    guid = guid or os.urandom(16)
    salt = salt or os.urandom(32)
    body = struct.pack("<HHHHI16sIHH", 36, len(DIALECTS), 1, 0, 0x40, guid, 112, 2, 0)
    body += struct.pack(f"<{len(DIALECTS)}H", *DIALECTS) + b"\x00\x00"
    preauth = struct.pack("<HHIHH", 1, 38, 0, 1, 32) + struct.pack("<H", 1) + salt
    encryption = struct.pack("<HHIHHH", 2, 6, 0, 2, 2, 1)
    return header(0, 0) + body + preauth + b"\x00\x00" + encryption


def session_setup_request():
    body = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 88, len(ntlm.SPNEGO_INIT), 0)
    return header(1, 1) + body + ntlm.SPNEGO_INIT


def frame(message):
    return struct.pack(">I", len(message)) + message


async def read_frame(reader):
    (length,) = struct.unpack(">I", await reader.readexactly(4))
    length &= 0x00FFFFFF
    if length > MAX_FRAME:
        raise ValueError("SMB frame over 64 KB")
    return await reader.readexactly(length)


def status_of(message):
    if len(message) < 64 or message[:4] != b"\xfeSMB":
        return None
    return struct.unpack_from("<I", message, 8)[0]


async def challenge(reader, writer):
    writer.write(frame(negotiate_request()))
    await writer.drain()
    reply = await read_frame(reader)
    if status_of(reply) != 0:
        return None
    writer.write(frame(session_setup_request()))
    await writer.drain()
    for _ in range(MAX_PENDING):
        reply = await read_frame(reader)
        status = status_of(reply)
        if status != STATUS_PENDING:
            break
    if status != STATUS_MORE_PROCESSING:
        return None
    return ntlm.parse_challenge(reply[64:])


async def lookup(ip, port, ctx):
    async with net.connection(ip, port, ctx.connect_timeout) as (reader, writer):
        parsed = await challenge(reader, writer)
    if not parsed:
        ctx.debug("no challenge", ip=ip, port=port)
        return
    for finding in ntlm.findings(ip, port, parsed, ctx):
        yield finding
