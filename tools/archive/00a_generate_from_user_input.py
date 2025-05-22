import os
import json
import csv

def main():
    print("[00a] Wprowadzenie danych wejściowych")
    technique_input = input("Podaj ID technik (np. T1059,T1566.001): ").strip()
    techniques = [tid.strip().upper() for tid in technique_input.split(",") if tid.strip()]

    if len(techniques) > 1:
        apt_mode = True
        apt_name = input("Podaj nazwę grupy APT (np. APT29): ").strip()
    else:
        apt_mode = False
        apt_name = None

    status = input("Podaj status (Pending/Audit/Tested): ").strip().capitalize()
    author = input("Podaj autora: ").strip()

    csv_path = os.path.join("tools", "enterprise_attack.csv")
    attack_data = {}
    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            attack_data[row["ID"].strip().upper()] = {
                "name": row["Name"].strip(),
                "tactics": [t.strip() for t in row["Tactics"].split(",") if t.strip()]
            }

    enriched = []
    for tid in techniques:
        info = attack_data.get(tid, {"name": "UNKNOWN", "tactics": []})
        enriched.append({
            "technique_id": tid,
            "technique_name": info["name"],
            "tactics": info["tactics"]
        })

    context = {
        "techniques": enriched,
        "apt_mode": apt_mode,
        "apt_name": apt_name or "SingleTechnique",
        "status": status,
        "author": author
    }

    os.makedirs("tools", exist_ok=True)
    with open("tools/input_context.json", "w", encoding="utf-8") as f:
        json.dump(context, f, indent=4, ensure_ascii=False)
    print("[00a] Zapisano tools/input_context.json")

if __name__ == "__main__":
    main()
