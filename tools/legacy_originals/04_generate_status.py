import csv
from pathlib import Path
from shared_utils import get_all_scenario_folders, load_json

OUTPUT_CSV = Path("mapping/mitre-navigator/status.csv")
FIELDS = ["Technique ID", "Name", "Tactics", "Status", "Linked Rule"]

def collect_tags():
    rows = []
    for folder in get_all_scenario_folders():
        tags_path = folder / "tags.json"
        data = load_json(tags_path)
        if not data:
            continue
        rows.append([
            data.get("id", ""),
            data.get("name", ""),
            ", ".join(data.get("tactics", [])),
            data.get("status", ""),
            data.get("linked_alert", data.get("linked_rule", ""))  # obsługuje oba przypadki
        ])
    return rows

def write_csv(rows):
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(FIELDS)
        writer.writerows(rows)
    print(f"[✓] Zapisano {len(rows)} rekordów do {OUTPUT_CSV}")

if __name__ == "__main__":
    tag_rows = collect_tags()
    write_csv(tag_rows)
