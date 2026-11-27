import base64
import binascii
import re
import struct

from ip2fqdn.common import Finding

SIGNATURE = b"NTLMSSP\x00\x02\x00\x00\x00"
NEGOTIATE = base64.b64decode("TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==")
NEGOTIATE_B64 = base64.b64encode(NEGOTIATE).decode("ascii")
SPNEGO_INIT = bytes.fromhex(
    "604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a0428") + NEGOTIATE
FLAG_UNICODE = 0x00000001
AV_FIELDS = {1: "nb_computer", 2: "nb_domain", 3: "dns_computer", 4: "dns_domain",
             5: "dns_tree"}
MAX_TOKEN = 64 * 1024
HEADER_CHALLENGE = re.compile(r"^(NTLM|Negotiate)\s+([A-Za-z0-9+/]+=*)$", re.IGNORECASE)


def parse_challenge(buffer):
    start = buffer.find(SIGNATURE)
    if start < 0:
        return None
    message = bytes(buffer[start:])
    if len(message) < 32:
        return None
    flags = struct.unpack_from("<I", message, 20)[0]
    result = {}
    target = _field(message, 12)
    if target:
        result["target"] = _decode(target, flags & FLAG_UNICODE)
    if len(message) >= 48:
        result.update(_av_pairs(_field(message, 40) or b""))
    return result


def _field(message, offset):
    length, _, buffer_offset = struct.unpack_from("<HHI", message, offset)
    if length == 0 or buffer_offset + length > len(message):
        return None
    return message[buffer_offset:buffer_offset + length]


def _av_pairs(data):
    found = {}
    position = 0
    while position + 4 <= len(data):
        av_id, av_len = struct.unpack_from("<HH", data, position)
        position += 4
        if av_id == 0 or position + av_len > len(data):
            break
        key = AV_FIELDS.get(av_id)
        if key and key not in found:
            value = _decode(data[position:position + av_len], True)
            if value:
                found[key] = value
        position += av_len
    return found


def _decode(raw, unicode):
    if unicode:
        if len(raw) % 2:
            raw = raw[:-1]
        text = raw.decode("utf-16-le", errors="replace")
    else:
        text = raw.decode("latin-1")
    return text.rstrip("\x00")


def challenge_from_headers(values):
    for value in values:
        for part in value.split(","):
            match = HEADER_CHALLENGE.match(part.strip())
            if not match or len(match[2]) > MAX_TOKEN * 4 // 3 + 4:
                continue
            try:
                token = base64.b64decode(match[2], validate=True)
            except (binascii.Error, ValueError):
                continue
            parsed = parse_challenge(token)
            if parsed is not None:
                return parsed
    return None


def findings_detail(parsed):
    rows = []
    if parsed.get("dns_computer"):
        rows.append((parsed["dns_computer"], "NTLM DNS computer name"))
    if parsed.get("nb_computer"):
        rows.append((parsed["nb_computer"], "NTLM NetBIOS computer name"))
    return rows


def zones(parsed):
    return [parsed[key] for key in ("dns_domain", "dns_tree") if parsed.get(key)]


def findings(ip, prefix, parsed, ctx):
    """Rows for the challenge's computer names (detail PREFIX NTLM ...); its domains become
    zone candidates (D20)."""
    ctx.learn_zones(zones(parsed))
    return [Finding(ip, name, f"{prefix} {detail}") for name, detail in findings_detail(parsed)]
