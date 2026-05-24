#!/usr/bin/env python3
import requests, os, sys
from urllib.parse import urlparse

OTX_API_KEY = "<enter the api key here>"
LISTS_DIR   = "/var/ossec/etc/lists/threat-intel"

def fetch_otx_iocs():
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    ips, domains, hashes = set(), set(), set()
    try:
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10"
        r = requests.get(url, headers=headers, timeout=60)
        if r.status_code == 200:
            for pulse in r.json().get("results", []):
                for ioc in pulse.get("indicators", []):
                    t = ioc.get("type", "")
                    v = ioc.get("indicator", "").strip().lower()
                    if t in ("IPv4", "IPv6"):                     ips.add(v)
                    elif t in ("domain", "hostname"):              domains.add(v)
                    elif t in ("FileHash-MD5", "FileHash-SHA256"): hashes.add(v)
    except Exception as e:
        print(f"    [!] OTX skipped: {e}")
    print(f"    OTX: {len(ips)} IPs, {len(domains)} domains, {len(hashes)} hashes")
    return ips, domains, hashes

def fetch_emerging_threats_ips():
    r = requests.get(
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        timeout=60
    )
    ips = set()
    for line in r.text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ips.add(line)
    return ips

def fetch_feodotracker_ips():
    r = requests.get(
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        timeout=60
    )
    ips = set()
    for line in r.text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ips.add(line)
    return ips

def fetch_abusech_hashes():
    r = requests.get(
        "https://bazaar.abuse.ch/export/txt/sha256/recent/",
        timeout=60
    )
    hashes = set()
    for line in r.text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and len(line) == 64:
            hashes.add(f"SHA256={line.lower()}")
    return hashes

def fetch_abusech_urls():
    r = requests.get(
        "https://urlhaus.abuse.ch/downloads/csv_recent/",
        timeout=60
    )
    domains = set()
    ips = set()
    for line in r.text.splitlines():
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        parts = line.replace('""', '').split('","')
        if len(parts) >= 3:
            url_field = parts[2].strip('"')
            try:
                parsed = urlparse(url_field)
                host = parsed.hostname
                if host:
                    import re
                    if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                        ips.add(host)
                    else:
                        domains.add(host.lower())
            except Exception:
                pass
    return domains, ips

def fetch_openphish_domains():
    r = requests.get(
        "https://openphish.com/feed.txt",
        timeout=60
    )
    domains = set()
    for line in r.text.splitlines():
        line = line.strip()
        if line.startswith("http"):
            try:
                host = urlparse(line).hostname
                if host:
                    domains.add(host.lower())
            except Exception:
                pass
    return domains

def write_cdb_list(filename, items, value="threat-intel"):
    path = os.path.join(LISTS_DIR, filename)
    with open(path, "w") as f:
        for item in sorted(items):
            f.write(f"{item}:{value}\n")
    print(f"[+] Wrote {len(items)} entries → {filename}")

def main():
    os.makedirs(LISTS_DIR, exist_ok=True)
    all_ips, all_domains, all_hashes = set(), set(), set()

    print("[*] Fetching OTX (subscribed pulses)...")
    otx_ips, otx_domains, otx_hashes = fetch_otx_iocs()
    all_ips |= otx_ips; all_domains |= otx_domains; all_hashes |= otx_hashes

    print("[*] Fetching Emerging Threats compromised IPs...")
    try:
        et_ips = fetch_emerging_threats_ips()
        all_ips |= et_ips
        print(f"    Emerging Threats: {len(et_ips)} IPs")
    except Exception as e:
        print(f"[!] Emerging Threats error: {e}")

    print("[*] Fetching Feodo Tracker botnet C2 IPs...")
    try:
        feodo_ips = fetch_feodotracker_ips()
        all_ips |= feodo_ips
        print(f"    Feodo Tracker: {len(feodo_ips)} IPs")
    except Exception as e:
        print(f"[!] Feodo Tracker error: {e}")

    print("[*] Fetching MalwareBazaar SHA256 hashes...")
    try:
        mb_hashes = fetch_abusech_hashes()
        all_hashes |= mb_hashes
        print(f"    MalwareBazaar: {len(mb_hashes)} hashes")
    except Exception as e:
        print(f"[!] MalwareBazaar error: {e}")

    print("[*] Fetching URLhaus malicious URLs...")
    try:
        uh_domains, uh_ips = fetch_abusech_urls()
        all_domains |= uh_domains
        all_ips |= uh_ips
        print(f"    URLhaus: {len(uh_domains)} domains, {len(uh_ips)} IPs")
    except Exception as e:
        print(f"[!] URLhaus error: {e}")

    print("[*] Fetching OpenPhish phishing domains...")
    try:
        op_domains = fetch_openphish_domains()
        all_domains |= op_domains
        print(f"    OpenPhish: {len(op_domains)} domains")
    except Exception as e:
        print(f"[!] OpenPhish error: {e}")

    print(f"\n[+] Final totals — IPs: {len(all_ips)}, Domains: {len(all_domains)}, Hashes: {len(all_hashes)}")

    if not any([all_ips, all_domains, all_hashes]):
        print("[!] All feeds failed — aborting.")
        sys.exit(1)

    write_cdb_list("malicious-ips.lst",     all_ips)
    write_cdb_list("malicious-domains.lst", all_domains)
    write_cdb_list("malicious-hashes.lst",  all_hashes)

    # Verify files are non-empty
    for fname in ["malicious-ips.lst", "malicious-domains.lst", "malicious-hashes.lst"]:
        path = os.path.join(LISTS_DIR, fname)
        count = sum(1 for _ in open(path))
        print(f"    Verified {fname}: {count} lines on disk")

    os.system("sudo /var/ossec/bin/wazuh-control reload")
    print("\n[+] Wazuh reloaded. Sync complete.")

if __name__ == "__main__":
    main()
