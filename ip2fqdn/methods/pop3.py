from ip2fqdn.proto import text

NAME = "pop3"
HELP = "POP3 STLS certificate names on 110; first NTLM step on 110 and 995 if offered"
KIND = "active"
PRESETS = ("default", "active", "cert")
PORTS = (110, 995)
PROTOCOL = "tcp"
NMAP_SERVICES = ("pop3", "pop3s")
RATE = 0
TIMEOUT = None
PHASE = 1
PARALLEL = None
NEEDS = ""
TLS_PORTS = (995,)


async def lookup(ip, port, ctx):
    implicit = port in TLS_PORTS or ctx.nmap_tls(ip, port)
    for finding in await text.converse(ip, port, ctx, _talk, implicit_tls=implicit):
        yield finding


async def _status(session):
    return (await session.text_line()).startswith("+OK")


async def _capabilities(session):
    """RFC 2449 CAPA: "+OK", then one capability per line, then "."."""
    await session.send("CAPA")
    if not await _status(session):
        return []
    lines = []
    while (line := await session.text_line()) != ".":
        lines.append(line)
    return lines


async def _talk(session):
    """RFC 1939; greeting names, APOP stamps included, are not read (D60)."""
    if not await _status(session):
        return
    seen = await _capabilities(session)
    stls = any(line.upper().split()[:1] == ["STLS"] for line in seen)
    if stls and not session.writer.get_extra_info("ssl_object"):
        await session.send("STLS")
        if not await _status(session):
            return
        await session.start_tls("STARTTLS")

        async def capabilities_again():  # RFC 2595 section 4: capabilities again after STLS
            seen.extend(await _capabilities(session))
        await session.later(capabilities_again)
    if text.offers_ntlm(seen, "SASL"):
        await session.later(lambda: _ntlm(session))
    await session.goodbye("QUIT", session.text_line)


async def _ntlm(session):
    """RFC 5034 AUTH with NTLM: stop after the challenge, cancel with "*"."""
    await session.send("AUTH NTLM")
    if not (await session.text_line()).startswith("+"):
        return
    await session.send(text.NTLM_TOKEN)
    reply = await session.text_line()
    if reply.startswith("+ "):
        session.add_challenge(reply[2:])
    await session.send("*")
    await session.text_line()
