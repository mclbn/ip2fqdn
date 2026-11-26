import ipaddress

IPV4_COMPATIBLE = ipaddress.ip_network("::/96")
NAT64 = ipaddress.ip_network("64:ff9b::/96")


def is_public(ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if address.version == 6 and (address in IPV4_COMPATIBLE or address in NAT64):
        return False
    return address.is_global and not address.is_multicast


def sort_key(ip):
    address = ipaddress.ip_address(ip)
    return (address.version, int(address))
