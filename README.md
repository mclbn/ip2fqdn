# ip2fqdn

Finds the FQDNs of a list of IP addresses and writes one CSV row per IP, name and source.
Design, decisions and sources: `ip2fqdn.org` (reference document).

Only run it against networks and services you are allowed to query. The `default` methods send
traffic to the listed IPs; the `api` methods send public addresses to third-party services.

## Install

Needs [uv](https://docs.astral.sh/uv/). Once, with Internet access, from the project folder:

    uv sync --locked                    # Python 3.14 and the locked dependencies
    uv run python -m ip2fqdn.ranges     # Cloudflare and CloudFront ranges for the shared label
    ln -s "$PWD/.venv/bin/ip2fqdn" ~/.local/bin/ip2fqdn

After that the tool works offline. Run the second command again to refresh the ranges
(`ip2fqdn/data/shared-ranges.txt`). uv keeps its Python in `~/.local/share/uv/python`
(`uv python uninstall 3.14` removes it).

## Examples

    ip2fqdn 10.0.1.0/24 --dns-server 10.0.0.10 -o names.csv
    ip2fqdn scans/*.xml extra.txt 10.9.9.9 --dns-server 10.0.0.10 -o names.csv
    ip2fqdn -m default,mdns --skip netbios 10.0.1.0/24 --dns-server 10.0.0.10
    ip2fqdn --zones corp.example --dns-server 10.0.0.10 10.0.1.0/24 -o names.csv
    SHODAN_API_KEY=... ip2fqdn -m passive public-ips.txt -o public.csv
    cat ips.txt | ip2fqdn - -m free -o public.csv      # run it again each day: see API cache
    ip2fqdn --list-methods

Inputs (any mix): IP, CIDR range (every address, network and broadcast included), `-` (IP
list on stdin), IP list file (one IP or CIDR per line, `#` comments), nmap or masscan XML
file. A file named like an IP is read with `./10.0.0.1`. Stderr says how each file was read.

## Options

| Option | Meaning |
|---|---|
| `-m`, `--methods LIST` | methods and presets to run (default: `default`) |
| `--skip LIST` | methods and presets to leave out |
| `-o`, `--output FILE` | CSV file (default: stdout); also enables the API cache |
| `--dns-server IP[:PORT][,...]` | DNS servers to query, `[::1]:5353` for IPv6 with a port (default: `/etc/resolv.conf`, see protected rule) |
| `--protected-dns` | DNS queries only to `--dns-server` servers, whatever the input |
| `--zones LIST` | zones for `axfr` and `dns-enum`; also transferred from their own name servers |
| `--no-forward-confirm` | no forward confirmation (`dns` column stays empty) |
| `--parallel N` | connections at once (default 500; at most 10 per IP, 50 queries per DNS server) |
| `--connect-timeout S` | TCP connect or UDP reply (default 3) |
| `--timeout S` | total time per method, IP and port (default 10; `smtp` 20) |
| `--<method>-timeout S` | same, for one method; wins over `--timeout` |
| `--<method>-ports LIST` | ports of `tls`, `rdp`, `smb`, `netbios`, `smtp`, `http`, `http-ntlm`, `mdns`; `default,10443` adds, `10443` replaces |
| `--shodan-search` | range searches (query credits) for /24 ranges where Shodan knows 10 IPs or more |
| `--max-ips N` | largest number of IPs (default 65536) |
| `--max-zones N` | largest number of zones (default 500) |
| `--debug` | masked technical log on stderr (`[debug]` lines) |
| `--list-methods`, `--version`, `-h` | information |

API keys come only from environment variables: `SHODAN_API_KEY`, `ONYPHE_API_KEY`,
`VIRUSTOTAL_API_KEY` (required by those methods), `OTX_API_KEY`, `URLSCAN_API_KEY`
(optional). A method named in `-m` without its key stops the run (exit 2); one pulled in by a
preset is skipped with a note.

## Methods

    name        state kind  phase   presets                     needs                 ports
    tls         on  active phase 1  default,active,cert         -                     443,8443,9443,636,465,993,995,5986
    rdp         on  active phase 1  default,active,windows,cert -                     3389
    smb         on  active phase 1  default,active,windows      -                     445
    netbios     on  active phase 1  default,active,windows      -                     137/udp
    smtp        on  active phase 1  default,active,cert         -                     25,587
    http        on  active phase 1  default,active              -                     80,8080
    http-ntlm   on  active phase 1  default,active,windows      -                     5985,5986,443
    mdns        off active phase 1  active                      -                     5353/udp
    ptr         on  dns    phase 1  default,dns,passive         DNS server            -
    axfr        on  dns    phase 2  default,dns                 DNS server            -
    dns-enum    on  dns    phase 2  default,dns,passive         DNS server            -
    nmap-names  on  file   phase 1  default,passive             nmap files            -
    sni         on  active phase 2  default,active,cert         -                     -
    shodan      off api    phase 1  api,passive                 SHODAN_API_KEY        -
    onyphe      off api    phase 1  api,passive                 ONYPHE_API_KEY        -
    internetdb  off api    phase 1  api,passive,free            -                     -
    otx         off api    phase 1  api,passive,free            OTX_API_KEY (opt.)    -
    virustotal  off api    phase 1  api,passive,free            VIRUSTOTAL_API_KEY    -
    urlscan     off api    phase 1  api,passive,free            URLSCAN_API_KEY (opt.) -
    mnemonic    off api    phase 1  api,passive,free            -                     -

Presets: `default` (no Internet needed), `all`, `active` (traffic to the listed IPs), `dns`,
`api`, `free`, `passive` (nothing sent to the listed IPs; `-m passive,axfr` adds transfers),
`windows`, `cert`.

With nmap input, ports a scan found closed or filtered are skipped, open ports are added by
service name, `tls` also tries every open TCP port no other method takes, and hosts reported
down by every file get no probe. Phase 2 (`axfr`, `dns-enum`, `sni`) starts when the quick
methods are done; zones come from `--zones`, from NTLM domain names and from the parent domain
of each name found, kept when a DNS server returns its SOA.

## Confidentiality rules

- Third-party services receive public addresses only; stderr gives the number skipped.
- Protected DNS rule: when any listed address is not public (or with `--protected-dns`), DNS
  queries go only to `--dns-server` servers, never to those of `/etc/resolv.conf`. A named
  server with a public address is used too, with a note: name only the client's own servers
  (never a public resolver such as 8.8.8.8) when the input holds internal addresses. Without a
  usable server, `ptr`, `axfr`, `dns-enum`, zone learning and forward confirmation are skipped
  and stderr says what to add.
- Zones named with `--zones` are also transferred from their own name servers, in every mode;
  only the zone name is sent.

## Output

CSV, UTF-8, header line, sorted by IP, then name, then source; every listed IP appears (an IP
without names gets a row with only `ip`). Control characters are written `\xNN`.

| Column | Content |
|---|---|
| `ip` | listed IP |
| `fqdn` | name, lowercased, no trailing dot |
| `source` | method |
| `detail` | where the name came from (`443 SAN`, `PTR @10.0.0.10`, `445 NTLM DNS computer name`), `; ` between places |
| `name_kind` | `dotted`, `short`, `local`, `wildcard` |
| `labels` | `generic` (IPv4 octets in the name), `placeholder` (shared device names), `shared` (Cloudflare or CloudFront address) |
| `dns` | forward confirmation: `match`, `other`, `none`, `error`, empty if not checked |
| `sni` | `served`, `not-served`, `error`, empty if not checked |
| `first_seen`, `last_seen` | local time with offset; empty when the source gives no date |

Stderr: how inputs were read, notes, then one summary line per method (IPs done, rows,
timeouts, errors, dropped names, method counters such as `certificates unreadable`), total
time and where the output went. A progress line is refreshed on a terminal.

API cache: with `-o FILE`, every third-party answer is appended to `FILE.api-cache`; a later
run with the same `-o FILE` asks each service only the IPs it has not answered yet. Delete the
file to refresh. Services with daily quotas (VirusTotal, urlscan, mnemonic) are spread over days
by running the same command again each day.

Ctrl-C or SIGTERM writes what was found so far ("interrupted: results incomplete"); a second
Ctrl-C quits at once.

## Exit codes

0 completed (also with no names, and when a quota stop left IPs for a later run), 1 fatal
error, 2 wrong usage or input error (before any traffic), 130 Ctrl-C, 143 SIGTERM.

## Sharing a debug run

`--debug` adds `[debug]` lines on stderr; values from inputs, targets and services are masked
(`IP4-1`, `HOST-2`, `PATH-3.xml`, `TEXT-4[len=15]`). The CSV and the other stderr lines are
not masked: share only the debug lines, for example `2>&1 >/dev/null | grep '^\[debug\]'`.

## First live runs

`LIVE-TESTS.md` lists the runs to make on real networks and services, what to send back, and
the points inferred from documentation that they check.

## Tests

From the project folder:

    .venv/bin/python -m pytest
    .venv/bin/ruff check .

Tests talk only to fake servers on 127.0.1.0/24 and ::1 (ports 1024 and above); a guard in
`tests/conftest.py` fails any other connection, name lookup or program launch, and asyncio
debug mode turns any step holding the event loop over 100 ms into a failure. API base
addresses are redirected to the fakes with `IP2FQDN_<METHOD>_URL` variables (not shown in
`--help`).
