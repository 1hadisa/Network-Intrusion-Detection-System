import json
import subprocess
from pathlib import Path
from datetime import datetime

# change these paths to match your setup 
CAPTURE_FOLDER = Path(r"C:\Users\User\Documents\captures")   # folder full of .pcapng files
SURICATA_PATH = r"C:\Program Files\Suricata\suricata.exe"
CONFIG_PATH = r"C:\Program Files\Suricata\suricata.yaml"
OUTPUT_FOLDER = Path(r"C:\Users\User\Documents\SuricataLogs")
EVE_FILE = OUTPUT_FOLDER / "eve.json"
INCIDENT_LOG = OUTPUT_FOLDER / "incident_log.txt"


def run_suricata_on_file(pcap_file: Path):
    """Runs Suricata on a single pcap file and waits for it to finish."""
    print(f"\n=== Analyzing {pcap_file.name} ===")
    # -r = read this pcap file (offline mode), -c = config/rules to use, -l = where to write eve.json/logs
    subprocess.run([SURICATA_PATH, "-r", str(pcap_file), "-c", CONFIG_PATH, "-l", str(OUTPUT_FOLDER)])


def print_all_alerts():
    """Reads eve.json from the start, prints every alert found, and saves them to incident_log.txt."""
    if not EVE_FILE.exists():
        print("No eve.json found — Suricata may not have produced any logs.")
        return
    # open the incident log once in "append" mode, so each run adds to it
    # instead of overwriting previous runs' history.
    with open(INCIDENT_LOG, "a") as log:
        log.write(f"\n----- Run at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} -----\n")
        with open(EVE_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue  # skip any broken/incomplete lines
                if event.get("event_type") != "alert":
                    continue
                signature = event.get("alert", {}).get("signature", "Unknown signature")
                src = event.get("src_ip", "Unknown")
                dst = event.get("dest_ip", "Unknown")
                message = f"[ALERT] {signature} | {src} -> {dst}"
                print(message)
                log.write(message + "\n")


def main():
    OUTPUT_FOLDER.mkdir(parents=True, exist_ok=True)
    # delete the old eve.json first so we only see alerts from THIS run,
    # not alerts left over from a previous analysis.
    if EVE_FILE.exists():
        EVE_FILE.unlink()
    pcap_files = list(CAPTURE_FOLDER.glob("*.pcapng"))
    if not pcap_files:
        print(f"No .pcapng files found in {CAPTURE_FOLDER}")
        return
    print(f"Found {len(pcap_files)} capture file(s) to analyze.")
    for pcap in pcap_files:
        run_suricata_on_file(pcap)
    print("\n=== ALL ALERTS ===")
    print_all_alerts()


if __name__ == "__main__":
    main()