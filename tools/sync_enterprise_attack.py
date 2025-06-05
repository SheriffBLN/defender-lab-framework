import json
import csv

# Pliki wejściowe/wyjściowe
JSON_PATH = "tools/helpers/enterprise-attack.json"
CSV_PATH = "tools/enterprise_attack.csv"

with open(JSON_PATH, "r", encoding="utf-8") as f:
    data = json.load(f)

fieldnames = ["ID", "Name", "Tactics", "Description", "MITRE Link"]
rows = []

for obj in data["objects"]:
    if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
        tid = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tid = ref.get("external_id")
        if not tid: continue
        name = obj.get("name", "")
        # Tactics (list)
        tactics = [phase["phase_name"].title() for phase in obj.get("kill_chain_phases", []) if phase.get("kill_chain_name") == "mitre-attack"]
        tactics_str = ", ".join(sorted(set(tactics)))
        # Description
        desc = obj.get("description", "").replace("\n", " ").replace("\r", " ").strip()
        # MITRE Link
        if "." in tid:
            base = tid.split(".")[0]
            link = f"https://attack.mitre.org/techniques/{base}/{tid.split('.')[1]}/"
        else:
            link = f"https://attack.mitre.org/techniques/{tid}/"
        rows.append({
            "ID": tid,
            "Name": name,
            "Tactics": tactics_str,
            "Description": desc,
            "MITRE Link": link
        })

with open(CSV_PATH, "w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)

print(f"[✓] Zapisano {len(rows)} technik do: {CSV_PATH}")
