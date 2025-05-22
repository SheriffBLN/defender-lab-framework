import json
import csv

INPUT = "enterprise-attack.json"
OUTPUT = "tools/mitre_techniques_full.csv"

with open(INPUT, "r", encoding="utf-8") as f:
    data = json.load(f)

techniques = []
for obj in data["objects"]:
    if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
        tid = next((ref["external_id"] for ref in obj.get("external_references", []) if ref["external_id"].startswith("T")), None)
        name = obj.get("name", "")
        tactics = [p["phase_name"].title() for p in obj.get("kill_chain_phases", []) if p["kill_chain_name"] == "mitre-attack"]
        if tid and tactics:
            techniques.append({
                "Technique ID": tid,
                "Name": name,
                "Tactics": ", ".join(sorted(set(tactics)))
            })

with open(OUTPUT, "w", newline="", encoding="utf-8") as out:
    writer = csv.DictWriter(out, fieldnames=["Technique ID", "Name", "Tactics"])
    writer.writeheader()
    writer.writerows(techniques)

print(f"[✓] Zapisano {len(techniques)} technik do: {OUTPUT}")
