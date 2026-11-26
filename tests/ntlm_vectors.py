import base64
import struct

V1 = base64.b64decode(
    "TlRMTVNTUAACAAAADAAMADgAAAAzgoriASNFZ4mrze8AAAAAAAAAACQAJABEAAAABgBwFwAAAA9TAGUAcgB2AGUA"
    "cgACAAwARABvAG0AYQBpAG4AAQAMAFMAZQByAHYAZQByAAAAAAA=")


def challenge(target="CORP", pairs=(), flags=0xE28A8235):
    target_bytes = target.encode("utf-16-le")
    info = b"".join(struct.pack("<HH", av_id, len(value.encode("utf-16-le")))
                    + value.encode("utf-16-le") for av_id, value in pairs)
    info += struct.pack("<HH", 0, 0)
    offset = 56
    head = struct.pack("<8sIHHIIQQHHI", b"NTLMSSP\x00", 2, len(target_bytes),
                       len(target_bytes), offset, flags, 0x0123456789ABCDEF, 0, len(info),
                       len(info), offset + len(target_bytes))
    return head + b"\x06\x01\xb1\x1d\x00\x00\x00\x0f" + target_bytes + info


def windows_challenge(computer="DC01", domain="corp.test"):
    return challenge("CORP", [(1, computer), (2, "CORP"), (3, f"{computer}.{domain}"),
                              (4, domain), (5, domain)])


def spnego_response(token):
    content = b"\x04" + _length(len(token)) + token
    inner = (b"\xa0\x03\x0a\x01\x01" + b"\xa1\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
             + b"\xa2" + _length(len(content)) + content)
    sequence = b"\x30" + _length(len(inner)) + inner
    return b"\xa1" + _length(len(sequence)) + sequence


def _length(value):
    if value < 128:
        return bytes([value])
    if value < 256:
        return b"\x81" + bytes([value])
    return b"\x82" + struct.pack(">H", value)
