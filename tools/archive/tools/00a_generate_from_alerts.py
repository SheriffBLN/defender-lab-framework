import os
from pathlib import Path
from shared_utils import write_json

ALERTS_DIR = Path("alerts")
SCENARIOS_DIR = Path("scenarios")

def extract_metadata(md_path):
    lines = md_path.read_text(encoding="utf-8").splitlines()
    tactics, technique_id, technique_name, status = [], "", "", "Pending"
    for line in lines[::-1]:
        if "Tactics:" in line:
            tactics = [t.strip() for t in line.split(":", 1)[-1].split(",")]
        elif "Technique ID:" in line:
            technique_id = line.split(":", 1)[-1].strip()
        elif "Technique Name:" in line:
            technique_name = line.split(":", 1)[-1].strip()
        elif "Status:" in line:
            status = line.split(":", 1)[-1].strip()
        if tactics and technique_id and technique_name:
            break
    return technique_id, technique_name, tactics, status

def generate_scenario_from_md(md_path):
    technique_id, technique_name, tactics, status = extract_metadata(md_path)
    if not (technique_id and technique_name and tactics):
        print(f"[!] Pominięto (brak metadanych): {md_path.name}")
        return

    name_base = md_path.stem.replace(" ", "").replace("-", "")
    folder_name = f"{technique_id}_{name_base}"
    scenario_path = SCENARIOS_DIR / folder_name
    if scenario_path.exists():
        print(f"[~] Istnieje: {folder_name} (pomijam)")
        return

    (scenario_path / "logs").mkdir(parents=True, exist_ok=True)
    (scenario_path / "attack.ps1").write_text(f"# Placeholder for {technique_id}\n", encoding="utf-8")
    (scenario_path / "detection.md").write_text(f"# Detection notes for {technique_id} ({technique_name})\n\nTODO", encoding="utf-8")

    tags = {
        "id": technique_id,
        "name": technique_name,
        "tactics": tactics,
        "status": status,
        "linked_alert": str(md_path.relative_to(".")).replace("\\", "/")
    }
    write_json(tags, scenario_path / "tags.json")
    print(f"[+] Utworzono: {scenario_path.name} ({status})")

def main():
    for md_path in ALERTS_DIR.rglob("*.md"):
        generate_scenario_from_md(md_path)

if __name__ == "__main__":
    main()
