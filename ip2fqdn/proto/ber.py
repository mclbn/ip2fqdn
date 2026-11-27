"""The small part of BER and DER (ITU-T X.690) that LDAP and CredSSP need.

Definite lengths only (RFC 4511 section 5.1 requires them for LDAP; DER always uses them),
single-byte tags, lengths up to 4 bytes. Reading never trusts a length beyond the data.
"""

SEQUENCE = 0x30
SET = 0x31
INTEGER = 0x02
OCTET_STRING = 0x04
BOOLEAN = 0x01
ENUMERATED = 0x0A


class BerError(ValueError):
    pass


def encode(tag, content):
    return bytes([tag]) + _length(len(content)) + content


def _length(value):
    if value < 0x80:
        return bytes([value])
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def sequence(*parts, tag=SEQUENCE):
    return encode(tag, b"".join(parts))


def integer(value, tag=INTEGER):
    size = max(1, (value.bit_length() + 8) // 8)
    return encode(tag, value.to_bytes(size, "big", signed=True))


def octets(data, tag=OCTET_STRING):
    return encode(tag, data)


def header_size(head):
    """Bytes taken by the tag and length at the start of head, or None if more are needed."""
    if len(head) < 2:
        return None
    if head[0] & 0x1F == 0x1F:
        raise BerError("multi-byte tag")
    first = head[1]
    if first < 0x80:
        return 2
    count = first & 0x7F
    if count == 0:
        raise BerError("indefinite length")
    if count > 4:
        raise BerError("length over 4 bytes")
    return 2 + count if len(head) >= 2 + count else None


def read(data, offset=0):
    """(tag, content, offset after the element) for the element at offset."""
    size = header_size(data[offset:offset + 6])
    if size is None:
        raise BerError("truncated header")
    first = data[offset + 1]
    length = first if first < 0x80 else int.from_bytes(data[offset + 2:offset + size], "big")
    start = offset + size
    end = start + length
    if end > len(data):
        raise BerError("length beyond the data")
    return data[offset], data[start:end], end


def children(content):
    """(tag, content) of each element inside a constructed element's content."""
    items = []
    offset = 0
    while offset < len(content):
        tag, inner, offset = read(content, offset)
        items.append((tag, inner))
    return items


def to_int(content):
    if not content or len(content) > 8:
        raise BerError("bad integer")
    return int.from_bytes(content, "big", signed=True)


async def read_element(reader, limit):
    """One whole element from a stream; BerError when it would exceed limit bytes."""
    head = await reader.readexactly(2)
    size = header_size(head)
    if size is None:
        head += await reader.readexactly(head[1] & 0x7F)
        size = header_size(head)
    first = head[1]
    length = first if first < 0x80 else int.from_bytes(head[2:size], "big")
    if size + length > limit:
        raise BerError(f"element over {limit} bytes")
    return head + await reader.readexactly(length)
