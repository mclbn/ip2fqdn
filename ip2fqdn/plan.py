import os

from ip2fqdn.common import UsageError

PRESETS = {
    "default": "runs when -m is not given; needs no Internet access",
    "all": "every implemented method",
    "active": "sends traffic to the listed IPs",
    "dns": "queries DNS servers only",
    "api": "calls third-party Internet services",
    "free": "third-party services needing no payment",
    "passive": "sends nothing to the listed IPs and nothing the target logs as hostile",
    "windows": "names from Windows protocols",
    "cert": "names from TLS certificates",
}


def members(preset, methods):
    if preset == "all":
        return [module for module in methods]
    return [module for module in methods if preset in module.PRESETS]


def expand(text, methods, option):
    by_name = {module.NAME: module for module in methods}
    chosen, named = [], set()
    for item in (part.strip() for part in text.split(",")):
        if not item:
            continue
        if item in by_name:
            found = [by_name[item]]
            named.add(item)
        elif item in PRESETS:
            found = members(item, methods)
        else:
            raise UsageError(f"{option}: unknown method or preset: {item} "
                             "(see --list-methods)")
        chosen.extend(module for module in found if module not in chosen)
    return chosen, named


def parse_ports(text, defaults, option):
    ports = []
    for item in (part.strip() for part in text.split(",")):
        if item == "default":
            ports.extend(defaults)
            continue
        try:
            port = int(item)
        except ValueError:
            raise UsageError(f"{option}: not a port number: {item}") from None
        if not 0 < port < 65536:
            raise UsageError(f"{option}: port out of range: {item}")
        ports.append(port)
    return sorted(set(ports))


def missing_key(module, environ=None):
    environ = os.environ if environ is None else environ
    key = getattr(module, "KEY", None)
    if key and getattr(module, "KEY_REQUIRED", False) and not environ.get(key):
        return key
    return None


class Plan:
    def __init__(self, methods, port_lists, named_zones):
        self.methods = methods
        self.by_name = {module.NAME: module for module in methods}
        self.port_lists = port_lists
        self.named_zones = named_zones

    def ports_for(self, module, ip, nmap):
        base = self.port_lists.get(module.NAME, ())
        host = nmap.host(ip)
        if host is None:
            return base
        if host.down_everywhere():
            return ()
        ports = {port for port in base if not nmap.skip_port(ip, module.PROTOCOL, port)}
        for (protocol, port), (service, tunnel) in host.open_ports.items():
            if protocol != module.PROTOCOL:
                continue
            if service in module.NMAP_SERVICES or (module.NAME == "tls" and tunnel == "ssl"):
                ports.add(port)
        if module.NAME == "tls":
            ports |= self._untaken_ports(host)
        return sorted(ports)

    def _untaken_ports(self, host):
        untaken = set()
        for (protocol, port), (service, _) in host.open_ports.items():
            if protocol != "tcp":
                continue
            if not any(self._takes(module, port, service) for module in self.methods
                       if hasattr(module, "lookup") and module.PROTOCOL == "tcp"):
                untaken.add(port)
        return untaken

    def _takes(self, module, port, service):
        return port in self.port_lists.get(module.NAME, ()) or service in module.NMAP_SERVICES

    def task_bound(self, modules, inputs):
        ports = sum(len(self.port_lists.get(module.NAME, ())) for module in modules)
        extra = sum(len(host.open_ports) for host in inputs.nmap.hosts.values())
        return len(inputs.ips) * ports + extra * len(modules)

    def lookup_tasks(self, modules, inputs):
        nmap = inputs.nmap
        for module in modules:
            if module.KIND != "active":
                continue
            base = set(self.port_lists.get(module.NAME, ()))
            special = {ip: set(self.ports_for(module, ip, nmap)) for ip in nmap.hosts}
            every = sorted(base.union(*special.values()))
            for port in every:
                for ip in inputs.ips:
                    if port in special.get(ip, base):
                        yield module, port, ip


def build_plan(args, methods, log, environ=None):
    chosen, named = expand(args.methods, methods, "-m")
    if args.skip:
        skipped, _ = expand(args.skip, methods, "--skip")
        chosen = [module for module in chosen if module not in skipped]
    final = []
    for module in chosen:
        key = missing_key(module, environ)
        if key and module.NAME in named:
            raise UsageError(f"{module.NAME}: environment variable {key} is not set")
        if key:
            log.note(f"{module.NAME} skipped: environment variable {key} is not set")
            continue
        final.append(module)
    port_lists = {}
    for module in methods:
        if not module.PORTS and not getattr(module, "HAS_PORTS", False):
            continue
        text = getattr(args, f"{module.NAME.replace('-', '_')}_ports", None)
        option = f"--{module.NAME}-ports"
        port_lists[module.NAME] = (parse_ports(text, module.PORTS, option) if text
                                   else list(module.PORTS))
    zones = []
    for item in (args.zones or "").split(","):
        item = item.strip().lower().rstrip(".")
        if item and item not in zones:
            zones.append(item)
    return Plan(final, port_lists, zones)
