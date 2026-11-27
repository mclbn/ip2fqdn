import re

from ip2fqdn.common import Finding
from ip2fqdn.names import check_name
from ip2fqdn.proto import text

NAME = "ftp"
HELP = "FTP greeting host name (printers, NAS, routers, Unix ftpd), AUTH TLS certificate names"
KIND = "active"
PRESETS = ("default", "active", "cert")
PORTS = (21,)
PROTOCOL = "tcp"
NMAP_SERVICES = ("ftp", "ftps")
RATE = 0
TIMEOUT = None
PHASE = 1
PARALLEL = None
NEEDS = ""
# "HOST FTP server (VERSION) ready", the layout of BSD ftpd and of most devices that name
# themselves; the words below take the host's place in that layout in nmap's fingerprints
# (nmap-service-probes, checked 2026-11-27): product names, MikroTik's default identity, and
# localhost on devices without a name.
BSD_LAYOUT = re.compile(r"^(\S+) FTP server \(", re.IGNORECASE)
VENDOR_LAYOUT = re.compile(r"\bFTP server\b.*\bready\b", re.IGNORECASE)
NOT_HOSTS = frozenset({"vxworks", "vxtarget", "nucleus", "isos", "prnet", "x5", "matrix",
                       "guildftpd", "mikrotik", "localhost"})


def greeting_name(line):
    """The host name opening a 220 greeting line (D61), or None.

    BSD layout: the first word, unless it is a product name. Vendor layouts ("HOST Lexmark T650
    FTP Server 1.0 ready."): the first word only when it holds a dot, since a product name can
    stand there too.
    """
    word = text.greeting_word(line)
    if word is None or check_name(word) is None:
        return None
    if BSD_LAYOUT.match(line):
        return None if word.lower() in NOT_HOSTS else word
    if "." in word and VENDOR_LAYOUT.search(line):
        return word
    return None


async def lookup(ip, port, ctx):
    implicit = ctx.nmap_tls(ip, port)
    for finding in await text.converse(ip, port, ctx, _talk, implicit_tls=implicit):
        yield finding


async def _talk(session):
    code, lines = await session.numeric_reply(free_lines=True)
    if code != 220:
        if code is not None:
            await _quit(session)
        return
    for line in lines:
        name = greeting_name(line)
        if name:
            session.found.append(Finding(session.ip, name, f"{session.port} greeting"))
            break
    if not session.writer.get_extra_info("ssl_object"):
        await session.send("AUTH TLS")  # RFC 4217 section 4
        code, _ = await session.numeric_reply(free_lines=True)
        if code == 234:
            await session.start_tls("AUTH TLS")
    await _quit(session)


async def _quit(session):
    await session.goodbye("QUIT", lambda: session.numeric_reply(free_lines=True))
