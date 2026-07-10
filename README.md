# Offline Pcap Analysis with Suricata
A Python automation tool that batch-processes a folder of packet captures (`.pcapng`) through [Suricata](https://suricata.io/), an open-source network IDS/IPS/NSM engine, and consolidates all detected alerts into a single, timestamped incident log.

Built as part of my internship to demonstrate offline network traffic analysis and automated threat-detection reporting.

## What this does
This tool performs **fully offline (static) pcap analysis** — no live network interface, no root/admin packet capture privileges required at analysis time. It:

1. Scans a folder for `.pcapng` capture files.
2. Runs each capture through Suricata using its offline read mode (`-r`), so Suricata processes the file once against its loaded rule set and exits.
3. Suricata writes all detected events (alerts, flows, protocol metadata, etc.) to `eve.json`.
4. The script parses `eve.json`, extracts only the `alert` events, and prints/logs each one as:
   ```
   [ALERT] <signature> | <source IP> -> <destination IP>
   ```
5. Every run appends a timestamped section to `incident_log.txt`, building a running history across multiple analysis sessions instead of overwriting previous results.

## Why offline analysis
Offline (pcap replay) analysis lets you run traffic that was already captured — with Wireshark, `tcpdump`, or downloaded from a public malware-sample repository — through Suricata's detection engine without needing a live interface or a mirrored/SPAN port. This is the standard workflow for:

- Post-incident forensic review of a specific capture.
- Testing and tuning detection rules against known malicious traffic samples.

## Requirements
- **Suricata** installed (tested on Windows).
- **Python 3.8+** (standard library only — see `requirements.txt`).
- A folder containing one or more `.pcapng` files.
- A valid `suricata.yaml` configuration file with a rule set enabled.

## Setup
1. Install Suricata: https://suricata.io/download/
2. Confirm a rule set is actually loaded in your `suricata.yaml` — an analysis run with zero alerts usually just means no rules are enabled, not that the traffic is clean.
3. Update the path constants at the top of `suricata_batch_analyzer.py`:

   | Variable | Description |
   |---|---|
   | `CAPTURE_FOLDER` | Folder containing the `.pcapng` files to analyze |
   | `SURICATA_PATH` | Full path to the `suricata.exe` (or `suricata` on Linux) binary |
   | `CONFIG_PATH` | Full path to your `suricata.yaml` config |
   | `OUTPUT_FOLDER` | Where Suricata's logs (`eve.json`, etc.) and the incident log will be written |

## Usage
```bash
python suricata_batch_analyzer.py
```

The script will:
- Process every `.pcapng` file in `CAPTURE_FOLDER` one by one.
- Print progress and alerts to the console as it goes.
- Save a full alert summary to `incident_log.txt` inside `OUTPUT_FOLDER`.

## Testing with real malicious traffic
To validate the tool against genuine threats rather than clean/benign traffic, test captures can be sourced from publicly available, purpose-built repositories such as:

- [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/) — labeled real-malware pcaps with full write-ups, widely used for IDS/IR training.
- [suricata-verify](https://github.com/OISF/suricata-verify) — Suricata's own official test pcaps, each crafted to trigger specific rule categories.
- [Stratosphere IPS / CTU-13 datasets](https://www.stratosphereips.org/datasets-overview) — labeled real botnet captures.
- [NETRESEC public pcap repository](https://www.netresec.com/?page=PcapFiles) — aggregated public pcaps including exploit/CTF traffic.

These captures are not included in this repo (see `.gitignore`) since traffic samples are large and, in some cases, contain live malicious payloads that shouldn't be committed to version control.

## Example output
```
Found 2 capture file(s) to analyze.

=== Analyzing suspicious_traffic_01.pcapng ===
=== Analyzing suspicious_traffic_02.pcapng ===

=== ALL ALERTS ===
[ALERT] ET SCAN Possible Nmap User-Agent Observed | 192.168.1.15 -> 192.168.1.1
[ALERT] ET POLICY Suspicious inbound to mySQL port 3306 | 203.0.113.4 -> 192.168.1.10
```

## Repo structure
```
.
├── suricata_batch_analyzer.py   # Main script
├── requirements.txt             # Python dependencies (none — stdlib only)
├── .gitignore                   
└── README.md
```

## Notes / Limitations
- Suricata overwrites `eve.json` on each invocation; this script deletes the old `eve.json` once at the start of a batch run, then reads the cumulative file at the end — so alerts from every pcap processed *within the same script run* appear together in one summary.
- Only `alert` type events are extracted from `eve.json`. Other event types Suricata can log (`flow`, `dns`, `tls`, `http`, etc.) are ignored by this script but remain available in the raw `eve.json` for deeper analysis.
- Detection quality depends entirely on the rule set configured in `suricata.yaml` — this tool does not ship or manage rules itself.
- This project intentionally does not implement live (`-i`) interface sniffing. That mode depends on the OS packet-capture driver (Npcap on Windows) being installed and configured correctly, which is an environment-specific concern separate from the analysis logic this tool provides.

## Possible next steps

- Parse additional event types (DNS, TLS/JA3, HTTP) for richer context per alert.
- Export alerts to CSV/JSON for ingestion into a SIEM or dashboard.
- Write a per-pcap `eve.json` (rename/move after each run) instead of one combined file, for cleaner per-capture attribution.
- Add CLI arguments instead of hardcoded path constants.
