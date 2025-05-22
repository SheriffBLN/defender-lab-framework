import csv
import json
from pathlib import Path

INPUT_CSV = "mapping/mitre-navigator/status.csv"
OUTPUT_JSON = "mapping/mitre-navigator/layer.json"
OUTPUT_CSV = "mapping/mitre-navigator/techniques.csv"

STATUS_COLORS = {
    "Tested": "#66ff66",
    "Audit": "#ffff66",
    "Pending": "#cccccc"
}

# Oficjalne identyfikatory taktyk w MITRE Navigator
TACTIC_MAP = {
    "Initial Access": "initial-access",
    "Execution": "execution",
    "Persistence": "persistence",
    "Privilege Escalation": "privilege-escalation",
    "Defense Evasion": "defense-evasion",
    "Credential Access": "credential-access",
    "Discovery": "discovery",
    "Lateral Movement": "lateral-movement",
    "Collection": "collection",
    "Command and Control": "command-and-control",
    "Exfiltration": "exfiltration",
    "Impact": "impact"
}

BASE_LAYER = {
    "version": "4.6",
    "name": "defender-lab-framework - Auto Generated Mapping",
    "domain": "mitre-enterprise",
    "description": "Warstwa wygenerowana na podstawie status.csv",
    "filters": {"platforms": ["Windows"]},
    "sorting": 0,
    "layout": {
        "layout": "side",
        "showID": True,
        "showName": True,
        "aggregateFunction": "average",
        "countUnscored": False
    },
    "hideDisabled": False,
    "techniques": [],
    "gradient": {
        "colors": ["#ffffff", "#66ff66"],
        "minValue": 0,
        "maxValue": 1
    },
    "legendItems": [
        {"label": "Tested in lab", "color": "#66ff66"},
        {"label": "Audit only", "color": "#ffff66"},
        {"label": "Pending", "color": "#cccccc"}
    ],
    "metadata": [
        {"name": "generated", "value": "true"}
    ]
}

def build_layer():
    techniques = []
    rows = []

    with open(INPUT_CSV, newline='', encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tid = row.get("Technique ID", "").strip()
            status = row.get("Status", "Pending").strip()
            comment = row.get("Linked Rule", "").strip()
            tactics_raw = row.get("Tactics", "").strip()

            if not tid:
                continue

            # Mapuj każdą taktykę na identyfikator Navigatora
            tactic_list = [TACTIC_MAP.get(t.strip()) for t in tactics_raw.split(",") if t.strip() in TACTIC_MAP]
            for tactic in tactic_list:
                techniques.append({
                    "techniqueID": tid,
                    "tactic": tactic,
                    "score": 1,
                    "comment": comment,
                    "color": STATUS_COLORS.get(status, "#cccccc")
                })

            rows.append([
                tid,
                row.get("Name", ""),
                tactics_raw,
                status,
                comment
            ])

    BASE_LAYER["techniques"] = techniques

    Path(OUTPUT_JSON).write_text(json.dumps(BASE_LAYER, indent=4), encoding="utf-8")
    print(f"[✓] Zapisano warstwę do: {OUTPUT_JSON}")

    with open(OUTPUT_CSV, "w", newline='', encoding="utf-8") as out:
        writer = csv.writer(out)
        writer.writerow(["Technique ID", "Name", "Tactics", "Status", "Comment"])
        writer.writerows(rows)
    print(f"[✓] Zapisano techniki do: {OUTPUT_CSV}")

if __name__ == "__main__":
    build_layer()
