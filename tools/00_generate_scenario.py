import argparse
import os
import json

TEMPLATE_TAGS = {
    "id": "",
    "name": "",
    "tactics": [],
    "status": "Pending",
    "linked_rule": ""
}

def generate_scenario(tech_id, name):
    folder_name = f"T{tech_id}_{name.replace(' ', '')}"
    path = os.path.join("scenarios", folder_name)
    os.makedirs(os.path.join(path, "logs"), exist_ok=True)

    with open(os.path.join(path, "attack.ps1"), "w") as f:
        f.write(f"# Atomic test for {tech_id} – {name}\n")

    with open(os.path.join(path, "detection.md"), "w") as f:
        f.write(f"# Detection for {tech_id} – {name}\n\n- TO DO\n")

    tags = TEMPLATE_TAGS.copy()
    tags["id"] = tech_id
    tags["name"] = name
    with open(os.path.join(path, "tags.json"), "w") as f:
        json.dump(tags, f, indent=4)

    print(f"[+] Created scenario folder: {path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate scenario folder and files")
    parser.add_argument("--id", required=True, help="MITRE technique ID (e.g., T1136.001)")
    parser.add_argument("--name", required=True, help="Scenario name (e.g., LocalAccountCreated)")
    args = parser.parse_args()
    generate_scenario(args.id, args.name)

# tools/generate_status.py

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
