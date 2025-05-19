from shared_utils import load_json, get_all_scenario_folders

REQUIRED_FIELDS = ["id", "name", "tactics", "status"]

def validate_tags():
    valid = 0
    errors = 0

    print("📋 Walidacja scenariuszy:")

    for folder in get_all_scenario_folders():
        tags_path = folder / "tags.json"
        if not tags_path.exists():
            print(f"[!] {folder.name}: brak pliku tags.json")
            errors += 1
            continue

        data = load_json(tags_path)
        if not data:
            print(f"[!] {folder.name}: błędny format JSON")
            errors += 1
            continue

        missing = [field for field in REQUIRED_FIELDS if field not in data]
        if missing:
            print(f"[!] {folder.name}: brakujące pola → {', '.join(missing)}")
            errors += 1
        else:
            print(f"[✓] {folder.name}: OK")
            valid += 1

    print(f"✅ Poprawnych scenariuszy: {valid}")
    print(f"❌ Błędnych lub niekompletnych: {errors}")

if __name__ == "__main__":
    validate_tags()
