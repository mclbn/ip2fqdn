# ip2fqdn: first live runs

The tests use fake servers built from specifications and documentation examples. These runs
check the tool on real networks and services, covering the most likely uses rather than every
option. Run them only against networks and services you are allowed to query.

## Before the runs

- Install as the README says, with Internet access, then check `ip2fqdn --list-methods`.
- Run every command with `--debug 2> tN.err`: debug lines are only added to stderr, the CSV and
  the other stderr lines stay the same. A `progress ...` line is written every 60 s; follow a
  long run with `tail -f tN.err` in another terminal.
- The default methods include `axfr`: zone transfer attempts, which DNS servers may log as an
  attack. If the client has not agreed to them, add `--skip axfr`.
- They also include `mssql`: SQL Server logs each attempt (error 17830, with your address). If
  the client has not agreed, add `--skip mssql`.

## What to send back after each run

1. Notes and summary (not masked: file names and DNS server addresses appear; edit as needed):

       grep -v '^\[debug\]' tN.err

2. Debug lines (already masked: `IP4-1`, `HOST-2`...). For a large run, send at least the
   lines that contain `refused`, `failed` or `error`:

       grep '^\[debug\]' tN.err

3. Row counts by source, name kind, forward confirmation and SNI check (no names or IPs):

       python3 -c 'import csv, sys, collections
       rows = [r for r in csv.DictReader(open(sys.argv[1], encoding="utf-8")) if r["source"]]
       counts = collections.Counter((r["source"], r["name_kind"], r["dns"] or "-",
                                     r["sni"] or "-") for r in rows)
       for key, n in sorted(counts.items()): print(*key, n)' tN.csv

4. A few real CSV rows per source when you can share them (names may be replaced; keep the
   `detail`, `name_kind`, `labels`, `dns` and `sni` columns as they are), and anything that
   looks wrong: a name missing, a name that should not be there, a run much slower than
   expected.

## Runs

### 1. Internal Windows network, IP range only

The core case. A /24 that holds domain controllers, file servers, an Exchange server if there
is one, a few Linux hosts and printers; a domain controller as DNS server.

    ip2fqdn 10.1.2.0/24 --dns-server <DC IP> -o t1.csv --debug 2> t1.err

Look for: `smb` and `netbios` rows for Windows hosts and Samba servers; `rdp` rows, including
`3389 NTLM DNS computer name` on hosts that require NLA; `ldap` rows on domain controllers (`389
rootDSE dnsHostName`); `http-ntlm` rows on Exchange (`443 /EWS/ ...`) and WinRM (5985, 5986);
`smtp`, `imap` and `pop3` NTLM rows on Exchange; `mssql` rows on SQL servers (`1433 NTLM DNS
computer name`); `ftp` greeting rows on printers, NAS and routers; `ptr` rows and the `dns`
column (`match` expected for most); `axfr` and `dns-enum` rows (zones learned from the NTLM and
LDAP domain names); `sni` values on HTTPS servers; timeouts per method in the summary.

### 2. Same range from an nmap scan

An existing scan, or `nmap -sS -sV -sC -oX scan.xml 10.1.2.0/24` (`-sC` includes the
`ssl-cert`, `smb-os-discovery` and `rdp-ntlm-info` scripts that `nmap-names` reads).

    ip2fqdn scan.xml --dns-server <DC IP> -o t2.csv --debug 2> t2.err

Look for: stderr starts with `scan.xml: nmap XML, N hosts`; the names of run 1 plus
`nmap-names` rows; fewer timeouts and a shorter total time than run 1; `netbios` rows still
present (a TCP-only scan does not skip UDP 137); HTTPS on non-standard ports found by `tls`.

### 3. Protected DNS rule (seconds)

An internal IP and no `--dns-server`. If you can, watch DNS traffic in another terminal:
`sudo tcpdump -ni any port 53`.

    ip2fqdn 10.1.2.10 -m ptr --debug 2> t3.err

Look for: the note `internal addresses in the input: DNS methods and checks need the client's
DNS servers; add --dns-server (resolv.conf lists ...)`, no `ptr` row, no packet in tcpdump.

### 4. Full internal scope (run time)

The whole list you would normally give the tool (several /24 or a few thousand IPs), as IPs or
as nmap files, with `--dns-server`.

    ip2fqdn scans/*.xml --dns-server <DC IP> -o t4.csv --debug 2> t4.err

Look for: total time and timeouts in the summary (the estimates in `ip2fqdn.org` are
not measured: about 13 minutes for 5,000 IPs without nmap input in the worst case); memory
use if you can watch it (`/usr/bin/time -v` gives the maximum resident size).

### 5. Internet-facing assets, default methods

The client's public IPs (a few dozen: web, mail and VPN servers, some behind a CDN) in
`public.txt`; no `--dns-server`, so the servers of `/etc/resolv.conf` are used.

    ip2fqdn public.txt -o t5.csv --debug 2> t5.err

Look for: `tls` and `sni` on real web servers (`served`, `not-served`); `smtp` names, including
mail servers behind postscreen or a greeting delay (20 s timeout), and `smtp` rows with `NTLM`
in `detail` on an exposed Exchange; `imap` and `pop3` STARTTLS certificates; `http` redirect
names; the `shared` label on Cloudflare or CloudFront addresses; `generic` labels on provider
PTR names.

### 6. Third-party services, twice

The same public IPs, plus one public IPv6 address if the client has one. Set the keys you
have; methods whose key is missing are skipped with a note. Duration: urlscan sends one search
every 36 s and VirusTotal one every 15 s, so 50 IPs take about 30 minutes.

    export SHODAN_API_KEY=... ONYPHE_API_KEY=... VIRUSTOTAL_API_KEY=...
    export OTX_API_KEY=... URLSCAN_API_KEY=...        # optional
    ip2fqdn public.txt -m passive -o t6.csv --debug 2> t6.err

Then run the same command again (same `-o t6.csv`), the same day or the next.

Look for, first run: Shodan debug lines `counts refused`, `batch lookups refused` and the
summary counter `facet counts not trusted`; Onyphe debug line `bulk requests refused`; any
`quota spent` or `switched off` note. Second run: `API cache: N cached answers used` and far
fewer requests.

## Optional runs

### 7. Named zone

The client's internal zone, with its agreement to zone transfers. The zone's own name servers
also receive transfer requests (only the zone name is sent).

    ip2fqdn 10.1.2.0/24 --zones corp.example --dns-server <DC IP> -o t7.csv --debug 2> t7.err

### 8. mDNS and LLMNR on your own segment

Only hosts on the segment you are plugged into answer. `llmnr` sends one multicast query per
IPv4 address of the range to the whole segment.

    ip2fqdn 192.168.1.0/24 -m default,mdns,llmnr --dns-server <DNS IP> -o t8.csv --debug 2> t8.err

Look for: `mdns` rows (`.local` names of Apple and Linux hosts, printers) and `llmnr` rows
(Windows computer names, Linux hosts running systemd-resolved).

### 9. Host names as input

A few of the client's public web names in `names.txt` (one per line, some behind a CDN if
possible), then the same file without `--dns-server`.

    ip2fqdn names.txt --dns-server 1.1.1.1 -o t9.csv --debug 2> t9.err
    ip2fqdn names.txt -m ptr

Look for: `input` rows (CNAME targets included) and the other names found for each address;
`input: N host names, M addresses, K without address` in the summary, and one row with an empty
`ip` per name without address (`dns` `none` or `error`); `shared` labels on CDN addresses.
Adding a name that does not exist to `names.txt` shows such a row. Second command: `error:
--dns-server missing: ...` and exit code 2 (`echo $?`).

## Points inferred from documentation, checked by these runs

- Shodan (run 6): the `ip` facet of `/shodan/host/count` (value format, and whether the per-IP
  counts add up to `total`); whether batch lookups are accepted; with `--shodan-search`,
  whether range searches are refused; the 404 body.
- Onyphe (run 6): whether `/bulk/summary/ip` is accepted (it was, on one licence, 2026-11-26),
  the NDJSON lines for IPs without data, the debug line `onyphe bulk lines` (line count, lines
  whose `ip` is a list, count per category), and the error code when credits run out (1005
  assumed).
- VirusTotal and OTX on IPv6 addresses (run 6); urlscan's 429 headers, and its per-minute and
  per-hour limits with a key (https://urlscan.io/user/quotas/ while logged in; the tool sends
  one search every 36 s, with or without a key); mnemonic's 402.
- `smb` against Windows and Samba (SPNEGO token accepted, challenge found), and SMB1-only hosts
  (no row expected) (runs 1, 2).
- `rdp` against a server set to "RDP security layer" (no row expected) (runs 1, 2).
- `netbios` from an ephemeral source port (Windows answers expected) (runs 1, 2).
- `http-ntlm` on Exchange: which path answers first; WinRM on 5985 and 5986 (run 1).
- `smtp` behind postscreen or a greeting delay (20 s timeout) (run 5).
- `dns-enum` and `axfr` against Windows DNS; forward confirmation with split views (runs 1, 7).
- Run times on a full list (run 4).
- `ldap`: the rootDSE answer of Active Directory and of other directory servers (runs 1, 2).
- `rdp`: the NTLM challenge in CredSSP with version 6 (nmap sends 0x60) (run 1).
- `smtp`, `imap`, `pop3`: whether Exchange lists NTLM before TLS, after it, or both (the tool
  tries NTLM only when listed) (runs 1, 5).
- `ftp`: the greeting rule on real printers, NAS and routers (run 1); share the greeting lines
  of devices that gave no row (`[debug]` lines do not hold them: a few `nc HOST 21` outputs).
- `mssql`: the encryption answer, TLS inside TDS on servers that force encryption (debug
  lines `no NTLM challenge` with `encryption=`, `unreadable reply`), and the error-log entry if
  the client's DBA can look (runs 1, 2).
- `llmnr`: whether Windows and systemd-resolved answer a multicast reverse query for their own
  address (run 8).
