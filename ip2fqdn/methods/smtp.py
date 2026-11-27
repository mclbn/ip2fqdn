from ip2fqdn.common import Finding
from ip2fqdn.proto import text

NAME = "smtp"
HELP = "SMTP greeting and EHLO names, STARTTLS certificate names, first NTLM step if offered"
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


async def lookup(ip, port, ctx):
    for finding in await text.converse(ip, port, ctx, _talk):
        yield finding


async def _talk(session):
    code, lines = await session.numeric_reply()
    if code is None:
        return
    _add_word(session, lines, "greeting")
    if code != 220:
        await _quit(session)
        return
    code, lines = await _ehlo(session)
    if code != 250:
        await _quit(session)
        return
    _add_word(session, lines, "EHLO")
    offered = text.offers_ntlm(lines[1:], "AUTH")
    if any(line.split()[:1] and line.split()[0].upper() == "STARTTLS" for line in lines[1:]):
        await session.send("STARTTLS")
        code, _ = await session.numeric_reply()
        if code != 220:
            await _quit(session)
            return
        await session.start_tls("STARTTLS")

        async def ehlo_again():
            nonlocal offered
            code, lines = await _ehlo(session)  # RFC 3207 section 4.2: capabilities again
            offered = offered or (code == 250 and text.offers_ntlm(lines[1:], "AUTH"))
        await session.later(ehlo_again)
    if offered:
        await session.later(lambda: _ntlm(session))
    await _quit(session)


async def _ehlo(session):
    await session.send(f"EHLO {text.ehlo_argument(session.writer)}")
    return await session.numeric_reply()


def _add_word(session, lines, where):
    """RFC 5321 section 4.3.1: the server's name is the first word of the greeting and of the
    first EHLO line."""
    name = text.greeting_word(lines[0]) if lines else None
    if name:
        session.found.append(Finding(session.ip, name, f"{session.port} {where}"))


async def _ntlm(session):
    """RFC 4954 AUTH with NTLM (Exchange): stop after the challenge, cancel with "*"."""
    await session.send("AUTH NTLM")
    code, _ = await session.numeric_reply()
    if code != 334:
        return
    await session.send(text.NTLM_TOKEN)
    code, lines = await session.numeric_reply()
    if code == 334 and lines:
        session.add_challenge(lines[0])
    await session.send("*")
    await session.numeric_reply()


async def _quit(session):
    await session.goodbye("QUIT", session.numeric_reply)
