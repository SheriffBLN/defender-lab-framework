import os
import json
from pathlib import Path

SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "scenarios"
REQUIRED_FIELDS = ["id", "name", "tactics", "status"]

def validate():
    valid = 0
    errors = 0
    for folder in SCENARIOS_DIR.iterdir():
        tags_path = folder / "tags.json"
        if tags_path.exists():
            with open(tags_path, "r", encoding="utf-8") as f:
                try:
                    data = json.load(f)
                    missing = [field for field in REQUIRED_FIELDS if field not in data]
                    if missing:
                        print(f"[!] {tags_path.name} → missing fields: {', '.join(missing)}")
                        errors += 1
                    else:
                        valid += 1
                except json.JSONDecodeError:
                    print(f"[!] {tags_path.name} → invalid JSON!")
                    errors += 1
        else:
            print(f"[!] {folder.name} → tags.json missing!")
            errors += 1
    print(f"[*] Valid: {valid}, Errors: {errors}")

if __name__ == "__main__":
    validate()
