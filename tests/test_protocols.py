"""Methods added at step 6 (D58 to D63): fakes built from the specifications they cite."""
import asyncio
import base64
import ssl
import struct

import dns.message
import dns.rdatatype
import dns.reversename
import dns.rrset
import fakes
import ntlm_vectors
from helpers import lookup
from hypothesis import given, settings
from hypothesis import strategies as st

from ip2fqdn.methods import ftp, imap, ldap, llmnr, mssql, pop3, rdp, smtp
from ip2fqdn.proto import ber, ntlm

# rootDSE values from nmap's ldap-rootdse sample output (scripts/ldap-rootdse.nse, a real Active
# Directory domain controller): the host name is in cqure.local, the naming contexts in cqure.net.
AD_ROOTDSE = {"dnsHostName": ["EDUSRV011.cqure.local"],
              "defaultNamingContext": ["DC=cqure,DC=net"],
              "rootDomainNamingContext": ["DC=cqure,DC=net"],
              "namingContexts": ["DC=cqure,DC=net", "CN=Configuration,DC=cqure,DC=net",
                                 "DC=DomainDnsZones,DC=cqure,DC=net"]}
OPENLDAP_ROOTDSE = {"namingContexts": ["dc=example,dc=org"]}


def ldap_entry(message_id, attributes):
    partial = [ber.sequence(ber.octets(name.encode()),
                            ber.sequence(*(ber.octets(value.encode()) for value in values),
                                         tag=ber.SET))
               for name, values in attributes.items()]
    entry = ber.sequence(ber.octets(b""), ber.sequence(*partial), tag=0x64)
    return ber.sequence(ber.integer(message_id), entry)


def ldap_done(message_id, code=0):
    result = ber.sequence(ber.encode(ber.ENUMERATED, bytes([code])), ber.octets(b""),
                          ber.octets(b""), tag=0x65)
    return ber.sequence(ber.integer(message_id), result)


def ldap_server(attributes, raw=None, seen=None):
    async def handle(reader, writer):
        try:
            request = await ber.read_element(reader, 4096)
            if seen is not None:
                seen.append(request)
            _, content, _ = ber.read(request)
            (_, message_id), (op_tag, search) = ber.children(content)[:2]
            fields = ber.children(search)
            assert op_tag == 0x63 and fields[0] == (ber.OCTET_STRING, b"")
            wanted = [value.decode() for _, value in ber.children(fields[7][1])]
            number = ber.to_int(message_id)
            if raw is not None:
                writer.write(raw)
                await writer.drain()
                return
            else:
                chosen = {name: values for name, values in attributes.items()
                          if name in wanted}
                writer.write(ldap_entry(number, chosen) + ldap_done(number))
            await writer.drain()
            await reader.read(10)
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
    return handle


def test_ldap_rootdse_names_and_domains():
    seen = []
    with fakes.FakeNetwork() as network:
        ad = network.tcp("127.0.1.70", 0, ldap_server(AD_ROOTDSE, seen=seen))
        other = network.tcp("127.0.1.71", 0, ldap_server(OPENLDAP_ROOTDSE))
        found, ctx = lookup(ldap, "127.0.1.70", ad)
        nothing, other_ctx = lookup(ldap, "127.0.1.71", other)
    assert [(f.name, f.detail) for f in found] == [
        ("EDUSRV011.cqure.local", f"{ad} rootDSE dnsHostName")]
    assert ctx.run.results.zone_candidates == ["cqure.net"]
    assert nothing == [] and other_ctx.run.results.zone_candidates == ["example.org"]
    _, content, _ = ber.read(seen[0])
    assert content.startswith(bytes.fromhex("02010163"))
    assert bytes.fromhex("04000a01000a0100020100020100010100870b6f626a656374436c617373") \
        in content


def test_ldap_garbage_reply_counted_not_raised():
    replies = (b"\x30\x84\xff\xff\xff\xff", b"\xff\xff\xff", ber.integer(5) + b"\n")
    with fakes.FakeNetwork() as network:
        ports = [network.tcp("127.0.1.72", 0, ldap_server({}, raw=raw)) for raw in replies]
        results = [lookup(ldap, "127.0.1.72", port) for port in ports]
    for found, ctx in results:
        assert found == [] and ctx.counts["unreadable replies"] == 1


def test_ldap_domain_rules():
    assert ldap.domain_of("DC=corp,DC=example") == "corp.example"
    assert ldap.domain_of("CN=Configuration,DC=corp,DC=example") is None
    assert ldap.domain_of("dc=a\\,b,dc=example") is None
    assert ldap.domains({"namingcontexts": ["o=org", "dc=example,dc=com"]}) == ["example.com"]


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=200))
def test_ldap_parser_never_crashes(data):
    try:
        ldap.parse_message(data)
    except ber.BerError:
        pass


def ts_request_reply(token=None, error_code=None):
    fields = [ber.encode(0xA0, ber.integer(6))]
    if token is not None:
        fields.append(ber.encode(0xA1, ber.sequence(ber.sequence(
            ber.encode(0xA0, ber.octets(token))))))
    if error_code is not None:
        fields.append(ber.encode(0xA4, ber.integer(error_code)))
    return ber.sequence(*fields)


def credssp_server(cert, selected, reply, seen):
    async def handle(reader, writer):
        try:
            await reader.readexactly(19)
            writer.write(bytes.fromhex("030000130ed00000123400021f0800") +
                         struct.pack("<I", selected))
            await writer.drain()
            await writer.start_tls(fakes.server_context(cert))
            if selected in (2, 8):
                seen.append(await ber.read_element(reader, 4096))
                writer.write(reply)
                await writer.drain()
            await reader.read(10)
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
    return handle


def test_rdp_ntlm_step_after_tls():
    cert = fakes.make_cert("TS01.corp.test")
    challenge = ntlm_vectors.windows_challenge("TS01", "corp.test")
    seen = []
    with fakes.FakeNetwork() as network:
        nla = network.tcp("127.0.1.74", 0, credssp_server(cert, 2, ts_request_reply(challenge),
                                                          seen))
        refused = network.tcp("127.0.1.74", 0, credssp_server(
            cert, 8, ts_request_reply(error_code=-1073741715), seen))
        tls_only = network.tcp("127.0.1.74", 0, credssp_server(cert, 1, b"", seen))
        found, ctx = lookup(rdp, "127.0.1.74", nla)
        cert_only, _ = lookup(rdp, "127.0.1.74", refused)
        plain, _ = lookup(rdp, "127.0.1.74", tls_only)
    assert [(f.name, f.detail) for f in found] == [
        ("TS01.corp.test", f"{nla} RDP CN"), ("TS01.corp.test", f"{nla} NTLM DNS computer name"),
        ("TS01", f"{nla} NTLM NetBIOS computer name")]
    assert ctx.run.results.zone_candidates == ["corp.test"]
    assert [f.detail for f in cert_only] == [f"{refused} RDP CN"]
    assert [f.detail for f in plain] == [f"{tls_only} RDP CN"]
    assert len(seen) == 2 and seen[0] == rdp.ts_request()
    # Same layout as nmap's rdp-ntlm-info request (scripts/rdp-ntlm-info.nse), version 6 for 0x60.
    assert rdp.ts_request()[:17].hex() == "3037a003020106a130302e302ca02a0428"
    assert rdp.ts_request()[17:] == ntlm.NEGOTIATE


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=200))
def test_credssp_parser_never_crashes(data):
    try:
        rdp.challenge_of(data)
    except ber.BerError:
        pass


def b64_challenge(computer="EXCH01", domain="corp.test"):
    return base64.b64encode(ntlm_vectors.windows_challenge(computer, domain))


NTLM_ROWS = [("EXCH01.corp.test", "NTLM DNS computer name"),
             ("EXCH01", "NTLM NetBIOS computer name")]


def rows(found, port):
    return [(f.name, f.detail.removeprefix(f"{port} ")) for f in found]


def test_smtp_ntlm_after_starttls_when_offered():
    cert = fakes.make_cert("mail.corp.test")
    exchange = [
        (None, b"220 mail.corp.test Microsoft ESMTP MAIL Service ready\r\n"),
        (b"EHLO", (b"250-mail.corp.test Hello [127.0.0.1]\r\n250-STARTTLS\r\n"
                   b"250 SIZE 1000\r\n")),
        (b"STARTTLS", b"220 2.0.0 SMTP server ready\r\n"), (None, "TLS"),
        (b"EHLO", b"250-mail.corp.test Hello\r\n250-AUTH NTLM LOGIN\r\n250 SIZE 1000\r\n"),
        (b"AUTH NTLM", b"334 NTLM supported\r\n"),
        (b"TlRMTVNTUAAB", b"334 " + b64_challenge() + b"\r\n"),
        (b"*", b"501 5.7.0 cancelled\r\n"), (b"QUIT", b"221 bye\r\n")]
    postfix = [(None, b"220 mx.corp.test ESMTP Postfix\r\n"),
               (b"EHLO", b"250-mx.corp.test\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n"),
               (b"QUIT", b"221 bye\r\n")]
    seen = []
    with fakes.FakeNetwork() as network:
        port = network.tcp("127.0.1.75", 0, fakes.script_server(exchange, cert))
        plain = network.tcp("127.0.1.75", 0, fakes.script_server(postfix, seen=seen))
        found, ctx = lookup(smtp, "127.0.1.75", port)
        other, _ = lookup(smtp, "127.0.1.75", plain)
    assert rows(found, port) == [("mail.corp.test", "greeting"), ("mail.corp.test", "EHLO"),
                                 ("mail.corp.test", "STARTTLS CN"), *NTLM_ROWS]
    assert ctx.run.results.zone_candidates == ["corp.test"]
    assert rows(other, plain) == [("mx.corp.test", "greeting"), ("mx.corp.test", "EHLO")]
    assert not [line for line in seen if line.upper().startswith(b"AUTH")]


IMAP_EXCHANGE = [
    (b"a1 CAPABILITY", (b"* CAPABILITY IMAP4 IMAP4rev1 AUTH=NTLM AUTH=GSSAPI LOGINDISABLED "
                        b"STARTTLS SASL-IR UIDPLUS ID UNSELECT CHILDREN IDLE\r\n"
                        b"a1 OK CAPABILITY completed.\r\n"))]


def test_imap_starttls_certificate_and_ntlm(monkeypatch):
    cert = fakes.make_cert("mail.corp.test")
    greeting = (None, b"* OK The Microsoft Exchange IMAP4 service is ready.\r\n")
    plain = [greeting, *IMAP_EXCHANGE,
             (b"a2 STARTTLS", b"a2 OK Begin TLS negotiation now.\r\n"), (None, "TLS"),
             (b"a3 CAPABILITY", (b"* CAPABILITY IMAP4 IMAP4rev1 AUTH=NTLM AUTH=PLAIN\r\n"
                                 b"a3 OK CAPABILITY completed.\r\n")),
             (b"a4 AUTHENTICATE NTLM", b"+ \r\n"),
             (b"TlRMTVNT", b"+ " + b64_challenge() + b"\r\n"),
             (b"*", b"a4 BAD Command Argument Error. 12\r\n"),
             (b"a5 LOGOUT", b"* BYE signing off.\r\na5 OK LOGOUT completed.\r\n")]
    implicit = [(None, "TLS"), greeting, *IMAP_EXCHANGE,
                (b"a2 AUTHENTICATE NTLM", b"+ \r\n"),
                (b"TlRMTVNT", b"+ " + b64_challenge() + b"\r\n"),
                (b"*", b"a2 BAD cancelled\r\n"), (b"a3 LOGOUT", b"* BYE\r\n")]
    cyrus = [(None, b"* OK mail.example.test Cyrus IMAP v2.4.17 server ready\r\n"),
             (b"a1 CAPABILITY", b"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\na1 OK done\r\n"),
             (b"a2 LOGOUT", b"* BYE\r\n")]
    with fakes.FakeNetwork() as network:
        first = network.tcp("127.0.1.76", 0, fakes.script_server(plain, cert))
        second = network.tcp("127.0.1.76", 0, fakes.script_server(implicit, cert))
        third = network.tcp("127.0.1.76", 0, fakes.script_server(cyrus))
        monkeypatch.setattr(imap, "TLS_PORTS", (second,))
        found, _ = lookup(imap, "127.0.1.76", first)
        tls_found, _ = lookup(imap, "127.0.1.76", second)
        nothing, _ = lookup(imap, "127.0.1.76", third)
    assert rows(found, first) == [("mail.corp.test", "STARTTLS CN"), *NTLM_ROWS]
    assert rows(tls_found, second) == NTLM_ROWS
    assert nothing == []


def test_pop3_stls_certificate_and_ntlm():
    cert = fakes.make_cert("mail.corp.test")
    exchange = [
        (None, b"+OK The Microsoft Exchange POP3 service is ready.\r\n"),
        (b"CAPA", b"+OK\r\nTOP\r\nUIDL\r\nSASL NTLM GSSAPI\r\nUSER\r\nSTLS\r\n.\r\n"),
        (b"STLS", b"+OK Begin TLS negotiation\r\n"), (None, "TLS"),
        (b"CAPA", b"+OK\r\nTOP\r\nSASL NTLM GSSAPI PLAIN\r\nUSER\r\n.\r\n"),
        (b"AUTH NTLM", b"+ \r\n"), (b"TlRMTVNT", b"+ " + b64_challenge() + b"\r\n"),
        (b"*", b"-ERR Protocol error. 14\r\n"), (b"QUIT", b"+OK signing off.\r\n")]
    dovecot = [(None, b"+OK Dovecot ready. <1896.697170952@mail.example.test>\r\n"),
               (b"CAPA", b"+OK\r\nTOP\r\nSASL PLAIN\r\n.\r\n"), (b"QUIT", b"+OK\r\n")]
    with fakes.FakeNetwork() as network:
        port = network.tcp("127.0.1.77", 0, fakes.script_server(exchange, cert))
        other = network.tcp("127.0.1.77", 0, fakes.script_server(dovecot))
        found, ctx = lookup(pop3, "127.0.1.77", port)
        nothing, _ = lookup(pop3, "127.0.1.77", other)
    assert rows(found, port) == [("mail.corp.test", "STARTTLS CN"), *NTLM_ROWS]
    assert ctx.run.results.zone_candidates == ["corp.test"]
    assert nothing == []


def test_ftp_greeting_rule():
    # Layouts from nmap's FTP fingerprints (nmap-service-probes, checked 2026-11-27).
    cases = {"host01 FTP server (Version 6.00LS) ready.": "host01",
             "gw-paris FTP server (MikroTik 6.48) ready": "gw-paris",
             "nas01.corp.test FTP server (NetBSD-ftpd 20100320) ready.": "nas01.corp.test",
             "printer.corp.test Lexmark T650 FTP Server 1.0 ready.": "printer.corp.test",
             "ftp.corp.test FTP server ready": "ftp.corp.test",
             "ET0021B7123456 Lexmark T650 FTP Server 1.0 ready.": None,
             "VxWorks FTP server (VxWorks 5.4) ready.": None,
             "MikroTik FTP server (MikroTik 6.48) ready": None,
             "localhost FTP server (Version 6.00LS) ready.": None,
             "(none) FTP server (GNU inetutils 1.9.4) ready.": None,
             "ProFTPD 1.3.5 Server (Debian) [::ffff:192.0.2.1]": None,
             "(vsFTPd 3.0.3)": None, "Microsoft FTP Service": None,
             "Serv-U FTP Server v15.1 ready...": None, "KONICA MINOLTA FTP server ready.": None,
             "": None}
    assert {line: ftp.greeting_name(line) for line in cases} == cases


def test_ftp_session_greeting_and_auth_tls():
    cert = fakes.make_cert("nas01.corp.test")
    netbsd = [(None, b"220-\r\n220 nas01 FTP server (NetBSD-ftpd 20100320) ready.\r\n"),
              (b"AUTH TLS", b"234 AUTH TLS OK.\r\n"), (None, "TLS"),
              (b"QUIT", b"221 Goodbye.\r\n")]
    banner = [(None, (b"220-Welcome\r\n  please behave\r\n"
                      b"220 host02.corp.test FTP server (Version 6.00) ready.\r\n")),
              (b"AUTH TLS", b"530 Please login with USER and PASS.\r\n"),
              (b"QUIT", b"221 Goodbye.\r\n")]
    with fakes.FakeNetwork() as network:
        first = network.tcp("127.0.1.78", 0, fakes.script_server(netbsd, cert))
        second = network.tcp("127.0.1.78", 0, fakes.script_server(banner))
        found, _ = lookup(ftp, "127.0.1.78", first)
        other, _ = lookup(ftp, "127.0.1.78", second)
    assert rows(found, first) == [("nas01", "greeting"), ("nas01.corp.test", "AUTH TLS CN")]
    assert rows(other, second) == [("host02.corp.test", "greeting")]


def test_llmnr_multicast_reverse_query(monkeypatch):
    owner = "127.0.1.81"
    queries = []

    def respond(data, address):
        query = dns.message.from_wire(data)
        queries.append(query)
        if query.question[0].name != dns.reversename.from_address(owner):
            return []
        reply = dns.message.make_response(query)
        reply.answer.append(dns.rrset.from_text(query.question[0].name, 30, "IN", "PTR",
                                                "WS042."))
        return [reply.to_wire()]

    with fakes.FakeNetwork() as network:
        port = network.udp("127.0.1.80", 0, respond)
        monkeypatch.setattr(llmnr, "GROUP_V4", "127.0.1.80")
        found, _ = lookup(llmnr, owner, port)
        nothing, _ = lookup(llmnr, "127.0.1.82", port, ["--connect-timeout", "0.2"])
        skipped, ctx = lookup(llmnr, "::1", port)
    assert [(f.name, f.detail) for f in found] == [("WS042", f"{port} LLMNR")]
    assert nothing == [] and skipped == []
    assert ctx.counts["IPv6 addresses not queried"] == 1
    assert queries[0].flags == 0 and queries[0].question[0].rdtype == dns.rdatatype.PTR


class ServerTls(mssql.Encrypted):
    """Server side of TLS inside TDS: handshake records in PRELOGIN packets, as TDS 7.2+."""

    def __init__(self, plain, cert):
        self.plain = plain
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        context = fakes.server_context(cert)
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_side=True)
        self.buffer = b""

    async def handshake(self):
        while True:
            kind, payload = await mssql.read_message(self.plain)
            assert kind == mssql.PRELOGIN
            self.incoming.write(payload)
            try:
                self.tls.do_handshake()
                done = True
            except ssl.SSLWantReadError:
                done = False
            await self._flush()
            if done:
                return


def tds_server(mode, reply, seen, cert=None):
    """mode "off": no encryption; "force": encryption required ([MS-TDS] 2.2.6.5 table)."""
    async def handle(reader, writer):
        try:
            plain = mssql.Plain(reader, writer)
            _, payload = await mssql.read_message(plain)
            asked = mssql.prelogin_option(payload, mssql.OPTION_ENCRYPTION)[0]
            seen.append(("asked", asked))
            if mode == "force":
                answer = mssql.ENCRYPT_REQ if asked == mssql.ENCRYPT_NOT_SUP else mssql.ENCRYPT_ON
            else:
                answer = mssql.ENCRYPT_NOT_SUP
            await plain.send(mssql.packets(mssql.TABULAR_RESULT, mssql.prelogin(answer)))
            if answer == mssql.ENCRYPT_REQ:
                return
            channel = plain
            if answer == mssql.ENCRYPT_ON:
                channel = ServerTls(plain, cert)
                await channel.handshake()
            kind, login = await mssql.read_message(channel)
            seen.append(("login", kind, login))
            await channel.send(mssql.packets(mssql.TABULAR_RESULT, reply))
            await reader.read(10)
        except (OSError, asyncio.IncompleteReadError, ssl.SSLError):
            pass
        finally:
            writer.close()
    return handle


def sspi_reply(token):
    return bytes([mssql.SSPI_TOKEN]) + struct.pack("<H", len(token)) + token


def test_mssql_ntlm_with_and_without_encryption():
    cert = fakes.make_cert("SQL01.corp.test")
    challenge = sspi_reply(ntlm_vectors.windows_challenge("SQL01", "corp.test"))
    plain_seen, forced_seen = [], []
    with fakes.FakeNetwork() as network:
        plain = network.tcp("127.0.1.84", 0, tds_server("off", challenge, plain_seen))
        forced = network.tcp("127.0.1.84", 0, tds_server("force", challenge, forced_seen, cert))
        refused = network.tcp("127.0.1.84", 0, tds_server("off", b"\xaa\x10\x00" + bytes(16),
                                                          []))
        found, ctx = lookup(mssql, "127.0.1.84", plain)
        tls_found, _ = lookup(mssql, "127.0.1.84", forced)
        nothing, _ = lookup(mssql, "127.0.1.84", refused)
    expected = [("SQL01.corp.test", "NTLM DNS computer name"),
                ("SQL01", "NTLM NetBIOS computer name")]
    assert rows(found, plain) == expected and rows(tls_found, forced) == expected
    assert ctx.run.results.zone_candidates == ["corp.test"]
    assert nothing == []
    assert [item[1] for item in forced_seen if item[0] == "asked"] == [
        mssql.ENCRYPT_NOT_SUP, mssql.ENCRYPT_ON]
    _, kind, login = plain_seen[1]
    assert kind == mssql.LOGIN7 and login == mssql.login7()
    # [MS-TDS] 2.2.6.4: fixed part of 94 bytes, fIntSecurity, SSPI data at the end.
    assert login[25] == 0x80 and struct.unpack_from("<HH", login, 78) == (94, 40)
    assert login[94:] == ntlm.NEGOTIATE


def test_mssql_unreadable_reply_counted():
    async def short_packet(reader, writer):
        await reader.read(100)
        writer.write(b"\x04\x01\x00\x02\x00\x00\x01\x00")
        await writer.drain()
        writer.close()

    with fakes.FakeNetwork() as network:
        port = network.tcp("127.0.1.85", 0, short_packet)
        found, ctx = lookup(mssql, "127.0.1.85", port)
    assert found == [] and ctx.counts["unreadable replies"] == 1


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=120), st.integers(0, 4))
def test_tds_parsers_never_crash(data, wanted):
    try:
        mssql.prelogin_option(data, wanted)
    except mssql.TdsError:
        pass
    mssql.sspi_challenge(data)
