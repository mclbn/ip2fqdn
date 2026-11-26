import ipaddress
import re

LABEL = re.compile(r"^[a-z0-9_-]{1,63}$")
MAX_NAME = 253
PLACEHOLDER_SUFFIXES = ("localhost", "localdomain", "invalid", "example", "example.com",
                        "example.net", "example.org", "routerlogin.net", "routerlogin.com",
                        "asusrouter.com")
PLACEHOLDER_EXACT = frozenset({
    "kubernetes", "kubernetes.default", "kubernetes.default.svc",
    "kubernetes.default.svc.cluster", "kubernetes.default.svc.cluster.local",
    "pfsense.home.arpa", "opnsense.internal", "mikrotik", "unifi", "synology", "synology.com"})
GENERIC_SEPARATORS = ("-", r"\.", "")


def check_name(raw):
    if not isinstance(raw, str) or not raw.isascii():
        return None
    name = raw.lower()
    name = name.removesuffix(".")
    if not name or len(name) > MAX_NAME:
        return None
    labels = name[2:].split(".") if name.startswith("*.") else name.split(".")
    if not all(LABEL.match(label) for label in labels):
        return None
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    return None


def name_kind(name):
    if name.startswith("*."):
        return "wildcard"
    if name == "local" or name.endswith(".local"):
        return "local"
    if "." not in name:
        return "short"
    return "dotted"


def is_placeholder(name):
    if name in PLACEHOLDER_EXACT:
        return True
    return any(name == suffix or name.endswith("." + suffix) for suffix in PLACEHOLDER_SUFFIXES)


def is_generic(name, ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if address.version != 4:
        return False
    octets = [_octet_pattern(int(part)) for part in str(address).split(".")]
    for order in (octets, octets[::-1]):
        for separator in GENERIC_SEPARATORS:
            pattern = r"(?<!\d)" + separator.join(order) + r"(?!\d)"
            if re.search(pattern, name):
                return True
    return False


def _octet_pattern(value):
    plain = str(value)
    padded = f"{value:03d}"
    if plain == padded:
        return plain
    return f"(?:{padded}|{plain})"


def parent_zone(name):
    if name_kind(name) not in ("dotted", "wildcard"):
        return None
    parent = name.split(".", 1)[1]
    if "." not in parent:
        return None
    return parent
