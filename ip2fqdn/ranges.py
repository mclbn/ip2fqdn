import ipaddress
import json
import os
import sys
import urllib.request

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
RANGES_FILE = os.path.join(DATA_DIR, "shared-ranges.txt")
CLOUDFLARE_URLS = ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6")
AWS_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
TIMEOUT = 30
MAX_BYTES = 32 << 20


def parse_cloudflare(text):
    networks = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            networks.append(str(ipaddress.ip_network(line, strict=False)))
    return networks


def parse_aws(text):
    document = json.loads(text)
    networks = []
    for key, field in (("prefixes", "ip_prefix"), ("ipv6_prefixes", "ipv6_prefix")):
        for entry in document.get(key, []):
            if entry.get("service") == "CLOUDFRONT" and entry.get(field):
                networks.append(str(ipaddress.ip_network(entry[field], strict=False)))
    return networks


def write_ranges(path, networks):
    unique = sorted(set(networks), key=lambda text: _network_key(ipaddress.ip_network(text)))
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        handle.write("# Cloudflare and AWS CloudFront ranges, written by python -m "
                     "ip2fqdn.ranges\n")
        handle.writelines(network + "\n" for network in unique)
    os.replace(temporary, path)
    return len(unique)


def _network_key(network):
    return (network.version, int(network.network_address), network.prefixlen)


class SharedRanges:
    def __init__(self, networks):
        self.tables = {4: [], 6: []}
        for network in networks:
            self.tables[network.version].append(
                (int(network.network_address), int(network.broadcast_address)))

    def contains(self, ip):
        address = ipaddress.ip_address(ip.split("%")[0])
        value = int(address)
        return any(start <= value <= end for start, end in self.tables[address.version])


def load(path=None):
    path = path or RANGES_FILE
    networks = []
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        networks.append(ipaddress.ip_network(line, strict=False))
                    except ValueError:
                        continue
    except OSError:
        return None
    return SharedRanges(networks)


def _fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "ip2fqdn setup"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return response.read(MAX_BYTES).decode("utf-8")


def main():
    networks = []
    for url in CLOUDFLARE_URLS:
        networks.extend(parse_cloudflare(_fetch(url)))
    networks.extend(parse_aws(_fetch(AWS_URL)))
    os.makedirs(DATA_DIR, exist_ok=True)
    count = write_ranges(RANGES_FILE, networks)
    print(f"{RANGES_FILE}: {count} shared ranges written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
