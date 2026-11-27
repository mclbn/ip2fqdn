import asyncio
import ssl
from contextlib import asynccontextmanager

READ_LIMIT = 64 * 1024
_contexts = {}


def tls_context(maximum=None):
    """Client context accepting any certificate and old servers; maximum caps the version."""
    context = _contexts.get(maximum)
    if context is None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        if maximum is not None:
            context.maximum_version = maximum
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
        _contexts[maximum] = context
    return context


@asynccontextmanager
async def connection(ip, port, connect_timeout, limit=READ_LIMIT):
    async with asyncio.timeout(connect_timeout):
        reader, writer = await asyncio.open_connection(ip, port, limit=limit)
    try:
        yield reader, writer
    finally:
        writer.transport.abort()


async def start_tls(writer, server_hostname=None):
    await writer.start_tls(tls_context(), server_hostname=server_hostname)
    ssl_object = writer.get_extra_info("ssl_object")
    return ssl_object.getpeercert(binary_form=True)
