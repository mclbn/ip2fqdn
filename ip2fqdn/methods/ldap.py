from ip2fqdn.common import Finding
from ip2fqdn.proto import ber, net

NAME = "ldap"
HELP = "anonymous LDAP rootDSE search on 389 and 3268: dnsHostName, domain names"
KIND = "active"
PRESETS = ("default", "active", "windows")
PORTS = (389, 3268)
PROTOCOL = "tcp"
NMAP_SERVICES = ("ldap", "globalcatLDAP")
RATE = 0
TIMEOUT = None
PHASE = 1
PARALLEL = None
NEEDS = ""
ATTRIBUTES = ("dnsHostName", "defaultNamingContext", "rootDomainNamingContext", "namingContexts")
MAX_MESSAGE = 64 * 1024
MAX_MESSAGES = 4
SEARCH_RESULT_ENTRY = 0x64
SEARCH_RESULT_DONE = 0x65


def search_request(message_id=1):
    """RFC 4511 section 4.5.1: base-object search of the rootDSE (empty DN), no bind."""
    body = (ber.octets(b"")
            + ber.encode(ber.ENUMERATED, b"\x00")  # scope baseObject
            + ber.encode(ber.ENUMERATED, b"\x00")  # neverDerefAliases
            + ber.integer(0) + ber.integer(0)  # no size or time limit
            + ber.encode(ber.BOOLEAN, b"\x00")  # typesOnly FALSE
            + ber.encode(0x87, b"objectClass")  # filter: present objectClass
            + ber.sequence(*(ber.octets(name.encode("ascii")) for name in ATTRIBUTES)))
    return ber.sequence(ber.integer(message_id), ber.encode(0x63, body))


def parse_message(message):
    """(protocolOp tag, {attribute name in lower case: [values]}) of one LDAPMessage."""
    tag, content, _ = ber.read(message)
    parts = ber.children(content) if tag == ber.SEQUENCE else []
    if len(parts) < 2 or parts[0][0] != ber.INTEGER:
        raise ber.BerError("not an LDAPMessage")
    op_tag, op_content = parts[1]
    attributes = {}
    if op_tag == SEARCH_RESULT_ENTRY:
        entry = ber.children(op_content)
        if len(entry) < 2 or entry[1][0] != ber.SEQUENCE:
            raise ber.BerError("bad SearchResultEntry")
        for attribute_tag, attribute in ber.children(entry[1][1]):
            fields = ber.children(attribute) if attribute_tag == ber.SEQUENCE else []
            if len(fields) < 2 or fields[0][0] != ber.OCTET_STRING or fields[1][0] != ber.SET:
                continue
            name = fields[0][1].decode("ascii", "replace").lower()
            attributes[name] = [value.decode("utf-8", "replace")
                                for value_tag, value in ber.children(fields[1][1])
                                if value_tag == ber.OCTET_STRING]
    return op_tag, attributes


def domain_of(dn):
    """corp.example for DC=corp,DC=example; None when the DN holds anything else."""
    labels = []
    for part in dn.split(","):
        key, _, value = part.strip().partition("=")
        if key.lower() != "dc" or not value or "\\" in value:
            return None
        labels.append(value)
    return ".".join(labels) or None


def domains(attributes):
    """Active Directory names its domains; other servers only list their naming contexts."""
    named = attributes.get("defaultnamingcontext", []) + \
        attributes.get("rootdomainnamingcontext", [])
    found = [domain_of(dn) for dn in named or attributes.get("namingcontexts", [])]
    return list(dict.fromkeys(domain for domain in found if domain))


async def lookup(ip, port, ctx):
    attributes = {}
    async with net.connection(ip, port, ctx.connect_timeout) as (reader, writer):
        writer.write(search_request())
        await writer.drain()
        try:
            for _ in range(MAX_MESSAGES):
                op_tag, values = parse_message(await ber.read_element(reader, MAX_MESSAGE))
                attributes.update(values)
                if op_tag != SEARCH_RESULT_ENTRY:
                    break
        except ber.BerError as error:
            ctx.count("unreadable replies")
            ctx.debug("unreadable reply", ip=ip, port=port, error=str(error))
    ctx.learn_zones(domains(attributes))
    for name in attributes.get("dnshostname", []):
        yield Finding(ip, name, f"{port} rootDSE dnsHostName")
