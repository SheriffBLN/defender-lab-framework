import os
import json
import csv

SCENARIO_DIR = "scenarios"
STATUS_CSV = "mapping/mitre-navigator/status.csv"

FIELDS = ["Technique ID", "Name", "Tactics", "Status", "Linked Rule"]

def collect_tags():
    rows = []
    for entry in os.listdir(SCENARIO_DIR):
        full_path = os.path.join(SCENARIO_DIR, entry, "tags.json")
        if os.path.exists(full_path):
            with open(full_path, "r") as f:
                data = json.load(f)
                rows.append([
                    data.get("id", ""),
                    data.get("name", ""),
                    ", ".join(data.get("tactics", [])),
                    data.get("status", ""),
                    data.get("linked_rule", "")
                ])
    return rows

def write_csv(rows):
    with open(STATUS_CSV, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(FIELDS)
        writer.writerows(rows)
    print(f"[+] Wrote {len(rows)} entries to {STATUS_CSV}")

if __name__ == "__main__":
    tag_rows = collect_tags()
    write_csv(tag_rows)
