"""
shared_utils.py – Wspólne funkcje dla wszystkich skryptów frameworka
"""

import json
from pathlib import Path

def load_json(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"[!] Błąd ładowania pliku JSON: {file_path} -> {e}")
        return None

def write_json(data, file_path):
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"[!] Błąd zapisu JSON: {file_path} -> {e}")

def get_all_scenario_folders(base_dir="scenarios"):
    base_path = Path(base_dir)
    return [f for f in base_path.iterdir() if f.is_dir() and not f.name.startswith(".")]

def get_scenario_by_id(scenario_id, base_dir="scenarios"):
    base_path = Path(base_dir)
    search_prefix = scenario_id if scenario_id.startswith("T") else f"T{scenario_id}"
    for folder in base_path.iterdir():
        if folder.is_dir() and folder.name.startswith(search_prefix + "_"):
            return folder
    return None
