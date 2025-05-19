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

BASE_LAYER = {
    "version": "4.3",
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
            tid = row.get("Technique ID", "")
            status = row.get("Status", "Pending")
            comment = row.get("Linked Rule", "")

            techniques.append({
                "techniqueID": tid,
                "score": 1,
                "comment": comment,
                "color": STATUS_COLORS.get(status, "#cccccc")
            })

            rows.append([
                tid,
                row.get("Name", ""),
                row.get("Tactics", ""),
                status,
                comment
            ])

    BASE_LAYER["techniques"] = techniques

    Path(OUTPUT_JSON).write_text(json.dumps(BASE_LAYER, indent=4), encoding="utf-8")
    print(f"[✓] Zapisano warstwę do: {OUTPUT_JSON}")

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as out:
        writer = csv.writer(out)
        writer.writerow(["Technique ID", "Name", "Tactics", "Status", "Comment"])
        writer.writerows(rows)
    print(f"[✓] Zapisano techniki do: {OUTPUT_CSV}")

if __name__ == "__main__":
    build_layer()
