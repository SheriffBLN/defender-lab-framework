import os
import json
import csv

STATUS_COLORS = {
    "Tested": "#66ff66",
    "Audit": "#ffff66",
    "Pending": "#cccccc"
}

LAYER = {
    "version": "4.3",
    "name": "defender-lab-framework - Auto Generated Mapping",
    "domain": "mitre-enterprise",
    "description": "Automatycznie wygenerowana warstwa na podstawie tags.json w folderze scenarios/",
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

CSV_ROWS = [["Technique ID", "Name", "Tactics", "Status", "Comment"]]

def main():
    scenario_root = "scenarios"
    if not os.path.exists(scenario_root):
        print("No scenarios/ directory found.")
        return

    for folder in os.listdir(scenario_root):
        tags_path = os.path.join(scenario_root, folder, "tags.json")
        if os.path.exists(tags_path):
            with open(tags_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                tid = data.get("id", "")
                name = data.get("name", "")
                status = data.get("status", "Pending")
                tactics = data.get("tactics", [])

                if not tid.startswith("T"):
                    continue

                comment = f"{name} – [status: {status}]"

                # Technika główna (jeśli istnieje podtechnika)
                parts = tid.split(".")
                if len(parts) == 2:
                    LAYER["techniques"].append({
                        "techniqueID": parts[0],
                        "score": 1,
                        "color": STATUS_COLORS.get(status, "#cccccc"),
                        "comment": comment
                    })
                    CSV_ROWS.append([parts[0], "(parent)", ", ".join(tactics), status, comment])

                # Podtechnika lub technika
                LAYER["techniques"].append({
                    "techniqueID": tid,
                    "score": 1,
                    "color": STATUS_COLORS.get(status, "#cccccc"),
                    "comment": comment
                })
                CSV_ROWS.append([tid, name, ", ".join(tactics), status, comment])

    # Zapis warstwy JSON
    output_json = "mapping/mitre-navigator/lab-detection-mapping-GENERATED.json"
    os.makedirs(os.path.dirname(output_json), exist_ok=True)
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(LAYER, f, indent=4)
    print(f"[+] Saved MITRE Navigator layer to: {output_json}")

    # Zapis CSV
    output_csv = "mapping/mitre-navigator/techniques.csv"
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(CSV_ROWS)
    print(f"[+] Saved techniques summary to: {output_csv}")

if __name__ == "__main__":
    main()
