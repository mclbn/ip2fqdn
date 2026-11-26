import ipaddress
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from xml.parsers import expat

from ip2fqdn.proto import certs

CHUNK = 1 << 20
SNIFF_LIMIT = 4 << 20
CONTROL_REFERENCE = re.compile(
    rb"&#(?:x0*([0-8bcefBCEF]|1[0-9a-fA-F])|0*([0-8]|1[124-9]|2[0-9]|3[01]));")
REFERENCE_TAIL = 12
OPEN_STATES = ("open", "open|filtered")
NTLM_KEYS = (("DNS_Computer_Name", "DNS computer name"),
             ("NetBIOS_Computer_Name", "NetBIOS computer name"))
NUL_TEXT = "\\x00"


class NotNmap(Exception):
    pass


class EntityRefused(Exception):
    pass


@dataclass
class HostRecord:
    ip: str
    status: str = "up"
    has_ports: bool = False
    open_ports: dict = field(default_factory=dict)
    names: list = field(default_factory=list)


@dataclass
class NmapFile:
    path: str
    kind: str
    start: int | None = None
    ranges: dict = field(default_factory=dict)
    hosts: dict = field(default_factory=dict)
    problem: dict | None = None


def read_file(path):
    with open(path, "rb") as handle:
        return read_xml(handle, path)


def read_xml(handle, path="-"):
    builder = _Builder(path)
    reader = _SubtreeReader(builder.on_root, builder.on_child)
    try:
        reader.feed(handle)
    except NotNmap:
        builder.file.kind = "not-nmap"
        return builder.file
    except EntityRefused:
        builder.file.kind = "refused"
        return builder.file
    except expat.ExpatError as error:
        if not reader.root_seen:
            builder.file.kind = "not-nmap"
            return builder.file
        builder.file.problem = {"line": error.lineno, "message": expat.ErrorString(error.code)}
    return builder.file


def _refuse_entity(*args):
    raise EntityRefused()


class _SubtreeReader:
    def __init__(self, on_root, on_child):
        parser = expat.ParserCreate()
        parser.buffer_text = True
        parser.StartElementHandler = self._start
        parser.EndElementHandler = self._end
        parser.CharacterDataHandler = self._text
        parser.EntityDeclHandler = _refuse_entity
        parser.UnparsedEntityDeclHandler = _refuse_entity
        parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
        self.parser = parser
        self.on_root = on_root
        self.on_child = on_child
        self.root_seen = False
        self.stack = []

    def feed(self, handle):
        pending = b""
        read = 0
        while chunk := handle.read(CHUNK):
            read += len(chunk)
            data, pending = _split_reference_tail(pending + chunk)
            self.parser.Parse(_visible_controls(data), False)
            if not self.root_seen and read >= SNIFF_LIMIT:
                raise NotNmap()
        self.parser.Parse(_visible_controls(pending), True)

    def _start(self, name, attrs):
        if not all(value.isascii() for value in attrs.values()):
            attrs = {key: _repair_text(value) for key, value in attrs.items()}
        if not self.root_seen:
            if name != "nmaprun":
                raise NotNmap()
            self.root_seen = True
            self.on_root(attrs)
            return
        element = ET.Element(name, attrs)
        if self.stack:
            self.stack[-1].append(element)
        self.stack.append(element)

    def _end(self, name):
        if not self.stack:
            return
        element = self.stack.pop()
        if element.text and not element.text.isascii():
            element.text = _repair_text(element.text)
        if not self.stack:
            self.on_child(element)

    def _text(self, data):
        if self.stack:
            element = self.stack[-1]
            element.text = (element.text or "") + data


def _split_reference_tail(data):
    cut = data.rfind(b"&", max(0, len(data) - REFERENCE_TAIL))
    if cut == -1 or b";" in data[cut:]:
        return data, b""
    return data[:cut], data[cut:]


def _visible_controls(data):
    return CONTROL_REFERENCE.sub(_control_text, data)


def _control_text(match):
    if match[1]:
        return b"\\x%02x" % int(match[1], 16)
    return b"\\x%02x" % int(match[2])


def _repair_text(text):
    try:
        return text.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return text


def _int(text):
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


class _Builder:
    def __init__(self, path):
        self.file = NmapFile(path, "nmap")

    def on_root(self, attrs):
        if attrs.get("scanner") == "masscan":
            self.file.kind = "masscan"
        self.file.start = _int(attrs.get("start"))

    def on_child(self, element):
        if element.tag == "host":
            self._on_host(element)
        elif element.tag == "scaninfo":
            protocol = element.get("protocol") or ""
            self.file.ranges.setdefault(protocol, []).extend(
                parse_ranges(element.get("services") or ""))

    def _on_host(self, element):
        ip = _host_ip(element)
        if ip is None:
            return
        host = self.file.hosts.get(ip)
        if host is None:
            host = self.file.hosts[ip] = HostRecord(ip)
        status = element.find("status")
        if status is not None:
            host.status = status.get("state") or "up"
        ports = element.find("ports")
        if ports is not None:
            host.has_ports = True
            for port in ports.findall("port"):
                _add_port(host, port)
        when = _int(element.get("starttime")) or self.file.start
        host.names.extend(_host_names(element, when))


def _host_ip(element):
    for address in element.findall("address"):
        if address.get("addrtype") in ("ipv4", "ipv6"):
            try:
                return str(ipaddress.ip_address(address.get("addr") or ""))
            except ValueError:
                return None
    return None


def _add_port(host, element):
    state = element.find("state")
    number = _int(element.get("portid"))
    if state is None or number is None or state.get("state") not in OPEN_STATES:
        return
    service = element.find("service")
    name = tunnel = None
    if service is not None and service.get("banner") is None:
        name = service.get("name")
        tunnel = service.get("tunnel")
    host.open_ports[(element.get("protocol") or "tcp", number)] = (name, tunnel)


def parse_ranges(text):
    ranges = []
    for item in text.split(","):
        low, _, high = item.partition("-")
        start, end = _int(low), _int(high or low)
        if start is not None and end is not None and 0 <= start <= end <= 65535:
            ranges.append((start, end))
    return ranges


def _host_names(element, when):
    names = []
    for entry in element.findall("hostnames/hostname"):
        kind = entry.get("type") or "?"
        names.append((entry.get("name"), f"nmap {kind}", when))
    for port in element.findall("ports/port"):
        number = port.get("portid")
        service = port.find("service")
        if service is not None and service.get("hostname"):
            names.append((service.get("hostname"), f"{number} nmap service", when))
        for script in port.findall("script"):
            names.extend((name, f"{number} nmap {detail}", when)
                         for name, detail in script_names(script))
    for script in element.findall("hostscript/script"):
        names.extend((name, f"nmap {detail}", when) for name, detail in script_names(script))
    return names


def script_names(script):
    script_id = script.get("id") or ""
    if script_id == "ssl-cert":
        return _ssl_cert_names(script)
    if script_id.endswith("-ntlm-info"):
        return _ntlm_names(script, script_id)
    if script_id == "smb-os-discovery":
        return _smb_names(script)
    return []


def _elem(node, key):
    for child in node:
        if child.tag == "elem" and child.get("key") == key:
            return child.text or ""
    return None


def _table(node, key):
    for child in node:
        if child.tag == "table" and child.get("key") == key:
            return child
    return None


def _ssl_cert_names(script):
    pem = _elem(script, "pem")
    if pem:
        names = certs.pem_names(pem)
        if names is not None:
            return [(name, f"ssl-cert {where}") for name, where in names]
    names = []
    subject = _table(script, "subject")
    if subject is not None and _elem(subject, "commonName"):
        names.append((_elem(subject, "commonName"), "ssl-cert CN"))
    extensions = _table(script, "extensions")
    for entry in extensions if extensions is not None else []:
        if _elem(entry, "name") == "X509v3 Subject Alternative Name":
            for item in (_elem(entry, "value") or "").split(", "):
                if item.startswith("DNS:"):
                    names.append((item[4:], "ssl-cert SAN"))
    return names


def _ntlm_names(script, script_id):
    names = []
    for node in script.iter():
        if node.tag not in ("script", "table"):
            continue
        for key, label in NTLM_KEYS:
            value = _elem(node, key)
            if value:
                names.append((value, f"{script_id} {label}"))
    return names


def _smb_names(script):
    names = []
    fqdn = _elem(script, "fqdn")
    if fqdn:
        names.append((fqdn.removesuffix(NUL_TEXT), "smb-os-discovery fqdn"))
    server = _elem(script, "server")
    if server:
        names.append((server.removesuffix(NUL_TEXT), "smb-os-discovery server"))
    return names


class NmapData:
    def __init__(self):
        self.files = []
        self.hosts = {}

    def add(self, nmap_file):
        index = len(self.files)
        self.files.append(nmap_file)
        for ip, record in nmap_file.hosts.items():
            merged = self.hosts.setdefault(ip, _MergedHost())
            merged.add(record, index)

    def host(self, ip):
        return self.hosts.get(ip)

    def is_down(self, ip):
        host = self.hosts.get(ip)
        return host is not None and host.down_everywhere()

    def covered(self, ip, protocol, port):
        host = self.hosts.get(ip)
        if host is None or not host.has_ports:
            return False
        for index in host.files:
            for start, end in self.files[index].ranges.get(protocol, ()):
                if start <= port <= end:
                    return True
        return False

    def skip_port(self, ip, protocol, port):
        host = self.hosts.get(ip)
        if host is None or (protocol, port) in host.open_ports:
            return False
        return self.covered(ip, protocol, port)

    def is_tls(self, ip, port):
        host = self.hosts.get(ip)
        if host is None:
            return False
        service = host.open_ports.get(("tcp", port))
        return service is not None and service[1] == "ssl"


class _MergedHost:
    def __init__(self):
        self.files = []
        self.statuses = []
        self.has_ports = False
        self.open_ports = {}
        self.names = []

    def add(self, record, index):
        self.files.append(index)
        self.statuses.append(record.status)
        self.has_ports = self.has_ports or record.has_ports
        for key, service in record.open_ports.items():
            if key not in self.open_ports or self.open_ports[key] == (None, None):
                self.open_ports[key] = service
        self.names.extend(record.names)

    def down_everywhere(self):
        return bool(self.statuses) and all(status == "down" for status in self.statuses)
