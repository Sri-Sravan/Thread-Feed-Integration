
# Threat Intelligence Integration into SIEM

> Integrating external threat feeds into Wazuh SIEM and correlating them with internal Sysmon logs for real-time detection of malicious IPs, domains, and file hashes.

---

## Overview

This project implements a complete threat intelligence pipeline on top of Wazuh 4.8.2. A Python script pulls IOCs from five open-source feeds daily, normalizes and deduplicates them into Wazuh CDB lookup lists, and six custom correlation rules match every incoming Sysmon event against 480K+ live IOCs in real time.

**25 confirmed alerts fired across all 6 detection rules during testing.**

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     External Threat Feeds                    │
│  Emerging Threats · Feodo Tracker · URLhaus ·               │
│  MalwareBazaar · OpenPhish · AlienVault OTX                 │
└──────────────────────────┬──────────────────────────────────┘
                           │  HTTP fetch (daily cron 02:00)
                           ▼
                  sync_feeds.py
                  (fetch → classify → deduplicate → write)
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Wazuh Manager (Ubuntu)                    │
│                                                             │
│  /var/ossec/etc/lists/                                      │
│    malicious-ips      (6,252 entries  → .cdb binary)        │
│    malicious-domains  (473,837 entries → .cdb binary)       │
│    malicious-hashes   (664 entries    → .cdb binary)        │
│                                                             │
│  threat-intel-rules.xml                                     │
│    Rules 100200–100205 → CDB lookup → Alert (level 12–15)  │
└──────────────────────────┬──────────────────────────────────┘
                           │  TLS 1514/TCP
                           ▼
              Windows 10 — Wazuh Agent + Sysmon
              EID 1 (process) · EID 3 (network)
              EID 7 (DLL load) · EID 22 (DNS)
```

---

## Lab Environment

| Component | Details |
|---|---|
| SIEM Server | Ubuntu 22.04 LTS — Wazuh 4.8.2 (Manager + Dashboard + Indexer) |
| Windows Endpoint | Windows 10 — Wazuh Agent v4.8.2 + Sysmon v15 |
| Network | 192.168.122.0/24 (KVM/libvirt) |
| Wazuh Server IP | 192.168.122.29 |
| Windows Agent IP | 192.168.122.101 |
| Agent ID | 002 (DESKTOP-M5T5582) |

---

## Threat Intelligence Feeds

| Feed | IOC Type | Source |
|---|---|---|
| Emerging Threats | Compromised IPs (~405) | `rules.emergingthreats.net/blockrules/compromised-ips.txt` |
| Feodo Tracker | Botnet C2 IPs (~5) | `feodotracker.abuse.ch/downloads/ipblocklist.txt` |
| URLhaus | Malicious domains + IPs (~14K) | `urlhaus.abuse.ch/downloads/csv_recent/` |
| MalwareBazaar | SHA256 hashes (~619) | `bazaar.abuse.ch/export/txt/sha256/recent/` |
| OpenPhish | Phishing domains (~271) | `openphish.com/feed.txt` |
| AlienVault OTX | IPs / domains / hashes | `otx.alienvault.com` (API key required) |

**Merged totals: 6,252 IPs · 473,837 domains · 664 hashes = 480K+ IOCs**

---

## Detection Rules

| Rule ID | Level | Sysmon EID | Field | IOC Type | MITRE |
|---|---|---|---|---|---|
| 100200 | 12 | EID 3 — Network | `win.eventdata.destinationIp` | Malicious IP outbound | T1071 |
| 100201 | 12 | EID 3 — Network | `win.eventdata.sourceIp` | Malicious IP inbound | T1071 |
| 100202 | 13 | EID 22 — DNS | `win.eventdata.queryName` | Malicious domain DNS | T1071.004 |
| 100203 | 13 | EID 3 — Network | `win.eventdata.destinationHostname` | Malicious hostname | T1071 |
| 100204 | 15 | EID 1 — Process | `win.eventdata.hashes` | Malware hash execution | T1204.002 |
| 100205 | 14 | EID 7 — DLL Load | `win.eventdata.hashes` | Malicious DLL load | T1574 |

---

## Results

All 6 rules confirmed firing end-to-end with real Sysmon events:

| Rule | Description | Alerts |
|---|---|---|
| 100200 | Malicious IP outbound | 3 |
| 100201 | Malicious IP inbound | 3 |
| 100202 | Malicious domain DNS query | 4 |
| 100203 | Malicious destination hostname | 2 |
| 100204 | Malware hash execution | 10 |
| 100205 | Malicious DLL/image load | 3 |
| **Total** | | **25** |

---

## Repository Structure

```
.
├── sync_feeds.py                  # Feed ingestion, normalization, CDB write
├── rules/
│   └── threat-intel-rules.xml    # Wazuh correlation rules (100200–100205)
├── config/
│   └── ossec.conf.snippet        # ossec.conf <ruleset> block with list registrations
└── README.md
```

---

## Setup

### Prerequisites

- Wazuh 4.8.2 manager installed on Ubuntu
- Windows 10 endpoint with Wazuh agent and Sysmon configured
- Python 3 with `requests` on the Wazuh server
- AlienVault OTX account (free) for the OTX feed

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/threat-intel-wazuh.git
cd threat-intel-wazuh
```

### 2. Install Python dependency

```bash
pip3 install requests --break-system-packages
```

### 3. Deploy the sync script

```bash
sudo mkdir -p /opt/threat-intel
sudo cp sync_feeds.py /opt/threat-intel/sync_feeds.py
```

Edit the script and set your OTX API key:

```python
OTX_API_KEY = "your_key_here"
```

Get a free key at [otx.alienvault.com](https://otx.alienvault.com) → Settings → API Key.

### 4. Run the sync script

```bash
sudo python3 /opt/threat-intel/sync_feeds.py
```

Expected output:
```
[*] Fetching OTX (subscribed pulses)...
    OTX: 15 IPs, 465273 domains, 45 hashes
[*] Fetching Emerging Threats compromised IPs...
    Emerging Threats: 405 IPs
[*] Fetching Feodo Tracker botnet C2 IPs...
    Feodo Tracker: 5 IPs
[*] Fetching MalwareBazaar SHA256 hashes...
    MalwareBazaar: 619 hashes
[*] Fetching URLhaus malicious URLs...
    URLhaus: 8296 domains, 5831 IPs
[*] Fetching OpenPhish phishing domains...
    OpenPhish: 271 domains

[+] Final totals — IPs: 6252, Domains: 473837, Hashes: 664
[+] Wrote 6252 entries → malicious-ips
[+] Wrote 473837 entries → malicious-domains
[+] Wrote 664 entries → malicious-hashes
[+] Wazuh reloaded. Sync complete.
```

### 5. Schedule daily refresh

```bash
sudo crontab -e
# Add:
0 2 * * * python3 /opt/threat-intel/sync_feeds.py >> /var/log/threat-intel-sync.log 2>&1
```

### 6. Register CDB lists in ossec.conf

Add inside the `<ruleset>` block in `/var/ossec/etc/ossec.conf`:

```xml
<list>etc/lists/malicious-ips</list>
<list>etc/lists/malicious-domains</list>
<list>etc/lists/malicious-hashes</list>
```

### 7. Deploy correlation rules

```bash
sudo cp rules/threat-intel-rules.xml /var/ossec/etc/rules/threat-intel-rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/threat-intel-rules.xml
```

### 8. Restart Wazuh manager

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```

Confirm rules loaded with no warnings:

```bash
sudo journalctl -u wazuh-manager --since "2 minutes ago" | grep -i "warn\|error"
```

---

## Verify Alerts

### Watch live alerts

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.log | grep -A 5 "Rule: 1002"
```

### Trigger a test alert — malicious IP (Rule 100200)

On the Windows endpoint (PowerShell as Administrator):

```powershell
curl.exe --max-time 3 http://1.10.209.143
```

Rule 100200 should fire within 5 seconds.

### Trigger a test alert — malicious domain DNS (Rule 100202)

```powershell
nslookup 0011.s3.cubbit.eu
```

Rule 100202 fires on the DNS query event (Sysmon EID 22).

### View in Wazuh Dashboard

1. Open Wazuh Dashboard → Discover
2. Filter: `rule.groups: threat_intel`
3. Time range: Last 24 hours
4. Add columns: `rule.id`, `rule.description`, `rule.level`, `data.win.eventdata.image`

### Alert count summary

```bash
sudo grep -a "Rule: 1002" /var/ossec/logs/alerts/alerts.log \
  | grep -oP "Rule: \d+" | sort | uniq -c
```

---

## Key Technical Notes

**CDB file ownership** — the sync script must write files as `wazuh:wazuh` with `660` permissions. Files must be in `/var/ossec/etc/lists/` directly (not a subdirectory) for Wazuh to auto-compile `.cdb` binaries on restart.

**Field path** — Wazuh 4.8.2 Sysmon rules use `win.eventdata.*` not `data.win.eventdata.*`. Confirm from the built-in ruleset:

```bash
sudo grep "destinationIp" /var/ossec/ruleset/rules/0595-win-sysmon_rules.xml
```

**Sysmon group name** — DNS event group is `sysmon_event_22` (underscore before 22), not `sysmon_event22`.

**Hash matching** — Sysmon stores hashes as `MD5=...,SHA256=...,IMPHASH=...`. The CDB `match_key` lookup matches substrings, so plain SHA256 hashes in the CDB will match against the full Sysmon hash string. To match exactly, prefix entries with `SHA256=` in the sync script.

---

## Limitations

| Limitation | Future Solution |
|---|---|
| No IOC confidence scoring — false positives possible | MISP TIP with confidence levels |
| No IOC expiry / TTL management | MISP lifecycle management |
| No source attribution in alerts | Tag CDB value with feed name |
| No STIX/TAXII standardization | MISP STIX/TAXII output to Wazuh module |
| Hash format is full Sysmon string not individual hash | Prefix entries with `SHA256=` in sync script |
| No automated response | Wazuh Active Response for IP blocking |

---

## Built With

- [Wazuh](https://wazuh.com) 4.8.2 — SIEM platform
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) v15 — Windows endpoint telemetry
- [AlienVault OTX](https://otx.alienvault.com) — threat intelligence feed
- [Abuse.ch](https://abuse.ch) — URLhaus + MalwareBazaar feeds
- [Emerging Threats](https://rules.emergingthreats.net) — IP blocklist
- [OpenPhish](https://openphish.com) — phishing URL feed
- Python 3 — feed ingestion and normalization

---
