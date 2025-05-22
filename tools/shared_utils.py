import json
from pathlib import Path

def load_json(path):
    path = Path(path)
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def write_json(data, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    json_str = json.dumps(data, indent=4)
    path.write_text(json_str, encoding="utf-8")

def get_all_scenario_folders(base_path="scenarios/"):
    """Zwraca listę folderów zawierających plik tags.json."""
    base = Path(base_path)
    if not base.exists():
        return []

    return [
        folder for folder in base.rglob("*")
        if folder.is_dir() and (folder / "tags.json").exists()
    ]
