import os
import json
import csv
from pathlib import Path

def main():
    print("[04a] Generowanie status.csv...")
    with open("tools/input_context.json", encoding="utf-8") as f:
        context = json.load(f)

    apt = context['apt_name']
    apt_mode = context.get('apt_mode', False)
    rows = []

    if apt_mode:
        scenario_base = Path("scenarios") / apt
        dirs = [d for d in scenario_base.iterdir() if d.is_dir()]
    else:
        scenario_base = Path("scenarios")
        dirs = [d for d in scenario_base.glob("*/*") if d.is_dir()]

    for folder in dirs:
        tags_file = folder / "tags.json"
        if not tags_file.exists():
            continue
        data = json.loads(tags_file.read_text(encoding='utf-8'))
        rows.append([
            data.get('id',''),
            data.get('name',''),
            ", ".join(data.get('tactics',[])),
            data.get('status',''),
            data.get('linked_rule','')
        ])

    out_csv = Path("mapping") / apt / "status.csv"
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(["Technique ID","Name","Tactics","Status","Linked Rule"])
        w.writerows(rows)
    print(f"[04a] Zapisano {len(rows)} rekordów do {out_csv}")

if __name__ == "__main__":
    main()
