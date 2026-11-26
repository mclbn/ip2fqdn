import asyncio
import struct

import fakes
import ntlm_vectors
from helpers import lookup
from hypothesis import given, settings
from hypothesis import strategies as st

from ip2fqdn.methods import smb
from ip2fqdn.proto import ntlm


def test_ntlm_spec_vectors():
    parsed = ntlm.parse_challenge(ntlm_vectors.V1)
    assert parsed == {"target": "Server", "nb_domain": "Domain", "nb_computer": "Server"}
    v2 = ntlm_vectors.V1[:32] + bytes(16) + ntlm_vectors.V1[48:56] + "Server".encode("utf-16-le")
    v2 = v2[:12] + struct.pack("<HHI", 12, 12, 56) + v2[20:]
    assert ntlm.parse_challenge(v2) == {"target": "Server"}


def test_ntlm_inside_spnego_and_headers():
    token = ntlm_vectors.windows_challenge()
    wrapped = ntlm_vectors.spnego_response(token)
    parsed = ntlm.parse_challenge(b"junk" + wrapped)
    assert parsed["dns_computer"] == "DC01.corp.test" and parsed["dns_tree"] == "corp.test"
    import base64
    value = "Basic realm=x, NTLM " + base64.b64encode(token).decode()
    assert ntlm.challenge_from_headers(["Negotiate", value])["nb_computer"] == "DC01"
    assert ntlm.challenge_from_headers(["NTLM !!!notbase64"]) is None


def test_ntlm_hostile_fields():
    token = bytearray(ntlm_vectors.windows_challenge())
    struct.pack_into("<HHI", token, 40, 0xFFFF, 0xFFFF, 0xFFFFFFF0)
    assert ntlm.parse_challenge(bytes(token)) == {"target": "CORP"}
    pairs = ntlm_vectors.challenge("X", [(3, "a\x00b"), (3, "second.test")])
    assert ntlm.parse_challenge(pairs)["dns_computer"] == "a\x00b"
    overrun = ntlm_vectors.challenge("X", [(3, "dc.test")])
    overrun = overrun[:-8] + struct.pack("<HH", 3, 500) + b"ab"
    assert "dns_computer" not in ntlm.parse_challenge(overrun)


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=400), st.integers(min_value=0, max_value=200))
def test_ntlm_parser_never_crashes(noise, cut):
    token = ntlm_vectors.windows_challenge()
    for data in (noise, b"NTLMSSP\x00\x02\x00\x00\x00" + noise, token[:cut], token + noise,
                 token[:cut] + noise):
        result = ntlm.parse_challenge(data)
        assert result is None or isinstance(result, dict)


def smb_reply(command, status, body):
    head = struct.pack("<4sHHIHHIIQIIQ16s", b"\xfeSMB", 64, 0, status, command, 1, 1, 0,
                       command, 0, 0, 0, bytes(16))
    message = head + body
    return struct.pack(">I", len(message)) + message


def smb_server(token, pending=0, negotiate_status=0):
    async def handle(reader, writer):
        try:
            await smb.read_frame(reader)
            body = struct.pack("<HHHH16sI", 65, 1, 0x0311, 0, bytes(16), 0) + bytes(41)
            writer.write(smb_reply(0, negotiate_status, body))
            await writer.drain()
            await smb.read_frame(reader)
            for _ in range(pending):
                writer.write(smb_reply(1, smb.STATUS_PENDING, struct.pack("<HBBI", 9, 0, 0, 0)))
            blob = ntlm_vectors.spnego_response(token)
            body = struct.pack("<HHHH", 9, 0, 72, len(blob)) + blob
            writer.write(smb_reply(1, smb.STATUS_MORE_PROCESSING, body))
            await writer.drain()
            await reader.read(10)
        except (asyncio.IncompleteReadError, OSError):
            pass
        finally:
            writer.close()
    return handle


def test_smb_names_and_zones():
    with fakes.FakeNetwork() as network:
        port = network.tcp("127.0.1.30", 0, smb_server(ntlm_vectors.windows_challenge(),
                                                        pending=2))
        found, ctx = lookup(smb, "127.0.1.30", port)
    assert [(f.name, f.detail) for f in found] == [
        ("DC01.corp.test", f"{port} NTLM DNS computer name"),
        ("DC01", f"{port} NTLM NetBIOS computer name")]
    assert ctx.run.results.zone_candidates == ["corp.test"]


def test_smb_refused_negotiate_gives_nothing():
    with fakes.FakeNetwork() as network:
        port = network.tcp("127.0.1.31", 0, smb_server(b"", negotiate_status=0xC00000BB))
        found, _ = lookup(smb, "127.0.1.31", port)
    assert found == []


def test_smb_request_bytes_match_research_vectors():
    guid = bytes(range(0x10, 0x20))
    salt = bytes(range(0x20, 0x40))
    negotiate = smb.negotiate_request(guid, salt)
    assert len(negotiate) == 174
    assert negotiate[64:80].hex() == "24000500010000004000000010111213"
    setup = smb.session_setup_request()
    assert len(setup) == 162 and setup[76:80] == b"\x58\x00\x4a\x00"
