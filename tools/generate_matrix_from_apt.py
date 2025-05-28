import os
import json
import csv

STIX_PATH = "tools/helpers/enterprise-attack.json"
CSV_PATH = "tools/enterprise_attack.csv"

def load_techniques_csv():
    data = {}
    with open(CSV_PATH, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tid = row["ID"].strip().upper()
            data[tid] = {
                "name": row["Name"].strip(),
                "tactics": [t.strip() for t in row["Tactics"].split(",") if t.strip()]
            }
    return data

def list_all_groups(stix_path):
    with open(stix_path, encoding="utf-8") as f:
        stix_json = json.load(f)
    objs = stix_json['objects']
    group_list = []
    for obj in objs:
        if obj.get("type") == "intrusion-set":
            mitre_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref.get("external_id")
            entry = {
                "name": obj.get("name"),
                "mitre_id": mitre_id,
                "id": obj.get("id")
            }
            group_list.append(entry)
    return group_list

def pick_group(stix_path):
    group_list = list_all_groups(stix_path)
    if not group_list:
        print("[Błąd] Brak poprawnych danych STIX lub nie znaleziono żadnej grupy APT.")
        return None
    print("=== Lista dostępnych grup (ID | nazwa) ===")
    for idx, g in enumerate(group_list):
        print(f"{idx+1:3}. {g['mitre_id'] or '---':6} | {g['name']}")
    print("------------------------------------------")
    inp = input("Podaj nazwę LUB ID grupy APT: ").strip().lower()
    for g in group_list:
        if inp == (g['name'] or '').lower() or inp == (g['mitre_id'] or '').lower():
            return g
    print(f"Nie znaleziono grupy: {inp}")
    return None

def extract_techniques_for_group(stix_path, group_entry):
    with open(stix_path, encoding="utf-8") as f:
        stix_json = json.load(f)
    objs = stix_json['objects']
    group_id = group_entry['id']
    uses = [r for r in objs if r.get("type") == "relationship" and r.get("source_ref") == group_id and r.get("relationship_type") == "uses"]
    techniques_ids = []
    for rel in uses:
        target = rel.get("target_ref")
        t_obj = next((o for o in objs if o.get("id") == target and o.get("type") == "attack-pattern"), None)
        if t_obj:
            ext_ref = next((r for r in t_obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
            if ext_ref and "external_id" in ext_ref:
                techniques_ids.append(ext_ref["external_id"].upper())
    return sorted(set(techniques_ids))

def main():
    print("=== Automatyczne generowanie macierzy ATT&CK dla grupy APT (bez stix2) ===")
    group_entry = pick_group(STIX_PATH)
    if not group_entry:
        print("Anulowano wybór.")
        return
    techniques_db = load_techniques_csv()
    try:
        techs = extract_techniques_for_group(STIX_PATH, group_entry)
    except Exception as e:
        print(f"Błąd: {e}")
        return
    print(f"Znaleziono {len(techs)} technik dla {group_entry['name']} ({group_entry['mitre_id']}): {', '.join(techs)}")
    apt_folder = group_entry['name'].replace(" ", "_")
    os.makedirs(os.path.join("mapping", apt_folder), exist_ok=True)
    status_path = os.path.join("mapping", apt_folder, "status.csv")
    with open(status_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["Technique ID","Name","Tactics","Status","Linked Rule","Author"])
        writer.writeheader()
        for tid in techs:
            if tid not in techniques_db:
                print(f"(!) Brak opisu techniki {tid} w CSV – pomijam")
                continue
            t = techniques_db[tid]
            writer.writerow({
                "Technique ID": tid,
                "Name": t["name"],
                "Tactics": ", ".join(t["tactics"]),
                "Status": "Pending",
                "Linked Rule": "",
                "Author": ""
            })
    print(f"[✓] Plik status.csv gotowy w mapping/{apt_folder}/status.csv")
    print("Możesz teraz odpalić tryb 3 (Update) w defender_lab.py, żeby wygenerować macierz i warstwę Navigatora!")

if __name__ == "__main__":
    main()
