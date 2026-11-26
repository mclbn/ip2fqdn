import ipaddress
import os
import socket
import subprocess

ALLOWED_V4 = ipaddress.ip_network("127.0.1.0/24")
ALLOWED_V6 = ipaddress.ip_address("::1")
NAME_LOOKUPS = ("gethostbyname", "gethostbyname_ex", "gethostbyaddr")
LAUNCHERS = ("system", "popen", "execv", "execve", "execvp", "execvpe", "execl", "execle",
             "execlp", "execlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe", "spawnl",
             "spawnle", "spawnlp", "spawnlpe", "posix_spawn", "posix_spawnp")


class Blocked(RuntimeError):
    pass


def _blocked(*args, **kwargs):
    raise Blocked("blocked by the test guard")


def allowed(family, address, binding=False):
    if family not in (socket.AF_INET, socket.AF_INET6):
        return True
    try:
        host = ipaddress.ip_address(str(address[0]).split("%")[0])
        port = int(address[1])
    except (ValueError, TypeError, IndexError):
        return False
    if family == socket.AF_INET and host not in ALLOWED_V4:
        return False
    if family == socket.AF_INET6 and host != ALLOWED_V6:
        return False
    return port >= 1024 or (binding and port == 0)


def _fake_server_reply(sock, address):
    """A fake server bound in 127.0.1.0/24 answers the kernel-chosen source 127.0.0.1."""
    try:
        local = sock.getsockname()
    except OSError:
        return False
    return (sock.family == socket.AF_INET and allowed(sock.family, local, True)
            and local[1] != 0 and str(address[0]) == "127.0.0.1" and int(address[1]) >= 1024)


def _checked(method, binding):
    def checked(self, *args, **kwargs):
        address = args[-1] if method.__name__ == "sendto" else args[0]
        if not allowed(self.family, address, binding) and not (
                method.__name__ == "sendto" and _fake_server_reply(self, address)):
            raise Blocked(f"network access blocked by the test guard: {address!r}")
        return method(self, *args, **kwargs)
    checked.__name__ = method.__name__
    return checked


def _numeric_getaddrinfo(real):
    def getaddrinfo(host, *args, **kwargs):
        if host is not None:
            try:
                ipaddress.ip_address(str(host.decode() if isinstance(host, bytes) else host)
                                     .split("%")[0])
            except ValueError:
                raise Blocked(f"name lookup blocked by the test guard: {host!r}") from None
        return real(host, *args, **kwargs)
    return getaddrinfo


def patches(block_programs):
    found = [(socket.socket, "connect", _checked(socket.socket.connect, False)),
             (socket.socket, "connect_ex", _checked(socket.socket.connect_ex, False)),
             (socket.socket, "sendto", _checked(socket.socket.sendto, False)),
             (socket.socket, "bind", _checked(socket.socket.bind, True)),
             (socket, "getaddrinfo", _numeric_getaddrinfo(socket.getaddrinfo))]
    found.extend((socket, name, _blocked) for name in NAME_LOOKUPS)
    if block_programs:
        found.append((subprocess.Popen, "__init__", _blocked))
        found.extend((os, name, _blocked) for name in LAUNCHERS if hasattr(os, name))
    return found


def install():
    for owner, name, value in patches(block_programs=True):
        setattr(owner, name, value)
