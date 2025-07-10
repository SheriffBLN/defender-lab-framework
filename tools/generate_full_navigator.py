import os
import csv
import json

# Kolory – możesz edytować HEX pod swoje preferencje
COLOR_MAP = [
    (0.5, "#b0b0b0"),    # szary (nie wykryto, status.csv tylko)
    (1, "#ffff00"),      # żółty 1-10
    (11, "#ffa500"),     # pomarańczowy 11-20
    (21, "#ff0000"),     # czerwony 21-50
    (51, "#0000ff"),     # niebieski 51-100
    (101, "#8000ff"),    # fiolet powyżej 100
]

def get_color(score):
    if score == 0 or score == 0.5:
        return "#b0b0b0"  # szary
    elif 1 <= score <= 10:
        return "#ffff00"  # żółty
    elif 11 <= score <= 20:
        return "#ffa500"  # pomarańczowy
    elif 21 <= score <= 50:
        return "#ff0000"  # czerwony
    elif 51 <= score <= 100:
        return "#0000ff"  # niebieski
    elif score > 100:
        return "#8000ff"  # fiolet
    else:
        return "#b0b0b0"

def load_score_map(score_csv_path):
    score_map = {}
    if os.path.isfile(score_csv_path):
        with open(score_csv_path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                tech = row.get("AttackTechniques") or row.get("Technique ID") or row.get("Technique")
                if tech:
                    try:
                        score_map[tech.strip()] = int(row.get("Count", 1))
                    except Exception:
                        score_map[tech.strip()] = 1
    return score_map

def generate_layer_for_csv(csv_path, output_json_path, score_map, mode="classic"):
    techniques = []
    with open(csv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tech_id = (
                row.get("Technique ID")
                or row.get("AttackTechniques")
                or row.get("Technique")
                or row.get("techniqueID")
                or row.get("ID")
            )
            if not tech_id:
                continue
            tech_id = tech_id.strip()
            # Opcje generowania
            if mode == "only_fired":
                count = score_map.get(tech_id, 0)
                if count > 0:
                    score = 1
                    color = get_color(score)
                    techniques.append({
                        "techniqueID": tech_id,
                        "score": score,
                        "color": color
                    })
                # Jeśli nie było wykrycia, NIE dodajemy tej techniki do warstwy.
            elif mode == "binary":
                count = score_map.get(tech_id, 0)
                score = 1 if count > 0 else 0
                color = get_color(score)
                techniques.append({
                    "techniqueID": tech_id,
                    "score": score,
                    "color": color
                })
            else:  # classic
                score = score_map.get(tech_id)
                if score is None:
                    score = 0.5
                color = get_color(score)
                techniques.append({
                    "techniqueID": tech_id,
                    "score": score,
                    "color": color
                })
    layer = {
        "name": os.path.basename(os.path.dirname(csv_path)),
        "domain": "mitre-enterprise",
        "techniques": techniques,
        "version": "4.6",
        "description": f"Layer wygenerowany automatycznie na podstawie {os.path.relpath(csv_path)} + last30days_alerts.csv"
    }
    with open(output_json_path, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=4)

def main():
    mapping_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "mapping"))
    score_csv_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tools", "helpers", "last30days_alerts.csv"))
    score_map = load_score_map(score_csv_path)
    print("Wybierz tryb generowania warstwy MITRE Navigator:")
    print("1) Klasyczna warstwa (score/kolory wg liczby wykryć, score=0.5 dla technik nieaktywowanych)")
    print("2) Warstwa binarna (score=1 jeśli technika wystąpiła, 0 jeśli nie)")
    print("3) Tylko wystąpienia – warstwa zawiera wyłącznie techniki z alertami (score=1), reszta pominięta")
    mode_input = input("Wybierz tryb (1/2/3): ").strip()
    mode = "classic"
    if mode_input == "2":
        mode = "binary"
    elif mode_input == "3":
        mode = "only_fired"
    found = False
    for root, dirs, files in os.walk(mapping_dir):
        for file in files:
            if file == "status.csv":
                csv_path = os.path.join(root, file)
                if mode == "binary":
                    output_json_path = os.path.join(root, "layer_binary.json")
                elif mode == "only_fired":
                    output_json_path = os.path.join(root, "layer_firedonly.json")
                else:
                    output_json_path = os.path.join(root, "layer.json")
                generate_layer_for_csv(csv_path, output_json_path, score_map, mode)
                print(f"[OK] Wygenerowano: {output_json_path}")
                found = True
    if not found:
        print("Nie znaleziono żadnego status.csv w mapping/ – sprawdź strukturę katalogu!")

if __name__ == "__main__":
    main()
