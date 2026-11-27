from ip2fqdn.proto import text

NAME = "imap"
HELP = "IMAP STARTTLS certificate names on 143; first NTLM step on 143 and 993 if offered"
KIND = "active"
PRESETS = ("default", "active", "cert")
PORTS = (143, 993)
PROTOCOL = "tcp"
NMAP_SERVICES = ("imap", "imaps")
RATE = 0
TIMEOUT = None
PHASE = 1
PARALLEL = None
NEEDS = ""
TLS_PORTS = (993,)


async def lookup(ip, port, ctx):
    implicit = port in TLS_PORTS or ctx.nmap_tls(ip, port)
    for finding in await text.converse(ip, port, ctx, _talk, implicit_tls=implicit):
        yield finding


class Imap:
    """RFC 9051: tagged commands; greeting names are not read (D60)."""

    def __init__(self, session):
        self.session = session
        self.number = 0

    async def command(self, line):
        """Untagged lines and the tagged status (OK, NO, BAD) of one command."""
        self.number += 1
        tag = f"a{self.number}"
        await self.session.send(f"{tag} {line}")
        untagged = []
        while True:
            reply = await self.session.text_line()
            if reply.startswith(f"{tag} "):
                return reply.split()[1:2] == ["OK"], untagged
            untagged.append(reply)

    async def capabilities(self):
        ok, untagged = await self.command("CAPABILITY")
        return {word.upper() for line in untagged if line.upper().startswith("* CAPABILITY ")
                for word in line.split()[2:]} if ok else set()


async def _talk(session):
    greeting = await session.text_line()
    if not greeting.upper().startswith("* OK"):
        return
    imap = Imap(session)
    seen = set()

    async def capabilities():
        seen.update(await imap.capabilities())
    await capabilities()
    if "STARTTLS" in seen and not session.writer.get_extra_info("ssl_object"):
        ok, _ = await imap.command("STARTTLS")
        if not ok:
            return
        await session.start_tls("STARTTLS")
        await session.later(capabilities)  # RFC 9051 section 6.2.1: capabilities again
    if "AUTH=NTLM" in seen:
        await session.later(lambda: _ntlm(imap))
    await session.goodbye(f"a{imap.number + 1} LOGOUT", session.text_line)


async def _ntlm(imap):
    """AUTHENTICATE NTLM (RFC 9051 section 6.2.2): stop after the challenge, cancel with "*"."""
    imap.number += 1
    tag = f"a{imap.number}"
    session = imap.session
    await session.send(f"{tag} AUTHENTICATE NTLM")
    if not (await session.text_line()).startswith("+"):
        return
    await session.send(text.NTLM_TOKEN)
    reply = await session.text_line()
    if reply.startswith("+ "):
        session.add_challenge(reply[2:])
    await session.send("*")
    while not (await session.text_line()).startswith(f"{tag} "):
        pass
