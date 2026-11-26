import asyncio
import datetime
import os
import socket
import ssl
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_CERTS = {}


def free_port(host="127.0.1.254"):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def make_cert(common_name, sans=()):
    key = (common_name, tuple(sans))
    if key in _CERTS:
        return _CERTS[key]
    private = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
               .public_key(private.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=2)))
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in sans]), False)
    cert = builder.sign(private, hashes.SHA256())
    directory = tempfile.mkdtemp(prefix="ip2fqdn-cert-")
    cert_path = os.path.join(directory, "cert.pem")
    key_path = os.path.join(directory, "key.pem")
    with open(cert_path, "wb") as handle:
        handle.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as handle:
        handle.write(private.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    _CERTS[key] = (cert_path, key_path, cert.public_bytes(serialization.Encoding.DER))
    return _CERTS[key]


def server_context(cert, sni_map=None, seen=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert[0], cert[1])
    if sni_map is not None or seen is not None:
        def choose(ssl_object, name, _):
            if seen is not None:
                seen.append(name)
            if sni_map and name in sni_map:
                other = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                other.load_cert_chain(sni_map[name][0], sni_map[name][1])
                ssl_object.context = other
        context.sni_callback = choose
    return context


class FakeNetwork:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.servers = []
        self.transports = []

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.call(self._close_all())
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.loop.close()

    def call(self, coroutine):
        return asyncio.run_coroutine_threadsafe(coroutine, self.loop).result(10)

    async def _close_all(self):
        for server in self.servers:
            server.close()
        for transport in self.transports:
            transport.close()
        others = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
        for task in others:
            task.cancel()
        await asyncio.gather(*others, return_exceptions=True)
        await asyncio.sleep(0)

    def tcp(self, host, port, handler, ssl_context=None):
        async def start():
            server = await asyncio.start_server(handler, host, port, ssl=ssl_context)
            self.servers.append(server)
            return server.sockets[0].getsockname()[1]
        return self.call(start())

    def udp(self, host, port, respond):
        class Protocol(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, address):
                for reply in respond(data, address) or ():
                    self.transport.sendto(reply, address)

        async def start():
            transport, _ = await self.loop.create_datagram_endpoint(
                Protocol, local_addr=(host, port))
            self.transports.append(transport)
            return transport.get_extra_info("sockname")[1]
        return self.call(start())


def tls_handler(context):
    async def handle(reader, writer):
        try:
            await reader.read(100)
        except (OSError, ssl.SSLError):
            pass
        finally:
            writer.close()
    return handle


def silent_handler():
    async def handle(reader, writer):
        try:
            await asyncio.sleep(60)
        finally:
            writer.close()
    return handle


class FakeDns:
    """Records: {(name, type): [value, ...]}; names absolute without trailing dot."""

    def __init__(self, records=None, transfers=None, silent=False):
        import collections
        self.records = collections.defaultdict(list)
        for key, values in (records or {}).items():
            self.records[(key[0].lower(), key[1].upper())].extend(values)
        self.transfers = transfers or {}
        self.silent = silent
        self.queries = []

    def answer(self, data):
        import dns.message
        import dns.rcode
        import dns.rrset
        query = dns.message.from_wire(data)
        question = query.question[0]
        name = question.name.to_text(omit_final_dot=True).lower()
        rdtype = dns.rdatatype.to_text(question.rdtype)
        self.queries.append((name, rdtype))
        response = dns.message.make_response(query)
        owner = name
        for _ in range(8):
            values = self.records.get((owner, rdtype))
            if values:
                response.answer.append(dns.rrset.from_text(owner + ".", 60, "IN", rdtype,
                                                           *values))
                break
            alias = self.records.get((owner, "CNAME"))
            if not alias:
                break
            response.answer.append(dns.rrset.from_text(owner + ".", 60, "IN", "CNAME",
                                                       alias[0]))
            owner = alias[0].rstrip(".").lower()
        if not response.answer and not any(key[0] == name for key in self.records):
            response.set_rcode(dns.rcode.NXDOMAIN)
        return response.to_wire()

    def udp_respond(self, data, address):
        if self.silent:
            return []
        return [self.answer(data)]

    def tcp_handler(self):
        import struct

        async def handle(reader, writer):
            try:
                while True:
                    (length,) = struct.unpack("!H", await reader.readexactly(2))
                    data = await reader.readexactly(length)
                    for message in self._tcp_messages(data):
                        writer.write(struct.pack("!H", len(message)) + message)
                    await writer.drain()
            except (asyncio.IncompleteReadError, OSError):
                pass
            finally:
                writer.close()
        return handle

    def _tcp_messages(self, data):
        import dns.message
        import dns.rcode
        import dns.rdatatype
        import dns.rrset
        query = dns.message.from_wire(data)
        question = query.question[0]
        if question.rdtype != dns.rdatatype.AXFR:
            return [self.answer(data)]
        zone = question.name.to_text(omit_final_dot=True).lower()
        self.queries.append((zone, "AXFR"))
        response = dns.message.make_response(query)
        if zone not in self.transfers:
            response.set_rcode(dns.rcode.REFUSED)
            return [response.to_wire()]
        soa = dns.rrset.from_text(zone + ".", 60, "IN", "SOA",
                                  f"ns1.{zone}. admin.{zone}. 1 60 60 60 60")
        messages = []
        records = [dns.rrset.from_text(owner + ".", 60, "IN", rdtype, value)
                   for owner, rdtype, value in self.transfers[zone]]
        first = dns.message.make_response(query)
        first.answer = [soa] + records[:2]
        messages.append(first.to_wire())
        rest = dns.message.make_response(query)
        rest.answer = records[2:] + [soa]
        messages.append(rest.to_wire())
        return messages


def start_dns(network, host, fake, port=0):
    port = network.udp(host, port, fake.udp_respond)
    network.tcp(host, port, fake.tcp_handler())
    return port
