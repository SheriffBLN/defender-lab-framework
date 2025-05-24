import csv
import json
from collections import Counter

input_path = "tools/helpers/last30days_alerts_2.csv"
output_path = "tools/helpers/last30days_alerts.csv"

technique_counter = Counter()

with open(input_path, encoding="utf-8") as f:
    reader = csv.DictReader(f)
    tech_col = None
    for col in ["AttackTechniques", "AlertTechniques"]:
        if col in reader.fieldnames:
            tech_col = col
            break
    if not tech_col:
        raise Exception("Nie znaleziono kolumny 'AttackTechniques' ani 'AlertTechniques' w pliku!")
    for row in reader:
        techs_raw = row.get(tech_col, "")
        try:
            techs = json.loads(techs_raw.replace("'", '"'))  # Fix for Defender's sometimes non-JSON quoting
        except Exception:
            techs = []
        for entry in techs:
            # Szukamy wzorca Txxxx. lub Txxxx
            import re
            m = re.search(r'(T\d{4}(?:\.\d{3})?)', entry)
            if m:
                tid = m.group(1).upper()
                technique_counter[tid] += 1

if not technique_counter:
    print("[!] Nie znaleziono żadnych technik Txxxx.x w pliku CSV!")
else:
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["AttackTechniques", "Count"])
        for tid, cnt in technique_counter.items():
            writer.writerow([tid, cnt])
    print(f"[✓] Wygenerowano plik: {output_path} ({len(technique_counter)} technik)")
