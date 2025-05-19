import argparse
import os
from pathlib import Path
from shared_utils import write_json

TEMPLATE_TAGS = {
    "id": "",
    "name": "",
    "tactics": [],
    "status": "Pending",
    "linked_alert": ""
}

def sanitize_id(tech_id):
    return tech_id if tech_id.upper().startswith("T") else f"T{tech_id}"

def generate_scenario(tech_id, name):
    tech_id = sanitize_id(tech_id)
    folder_name = f"{tech_id}_{name.replace(' ', '')}"
    scenario_path = Path("scenarios") / folder_name

    if scenario_path.exists():
        print(f"[!] Scenariusz już istnieje: {scenario_path}")
        return

    # Tworzenie struktury
    (scenario_path / "logs").mkdir(parents=True, exist_ok=True)

    # attack.ps1
    (scenario_path / "attack.ps1").write_text(f"# Atomic test for {tech_id} – {name}\n")

    # detection.md
    (scenario_path / "detection.md").write_text(f"# Detection for {tech_id} – {name}\n\n- TO DO\n")

    # tags.json
    tags = TEMPLATE_TAGS.copy()
    tags["id"] = tech_id
    tags["name"] = name
    write_json(tags, scenario_path / "tags.json")

    print(f"[+] Utworzono scenariusz: {scenario_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generator folderu scenariusza testowego")
    parser.add_argument("--id", required=True, help="ID techniki MITRE (np. T1136.001)")
    parser.add_argument("--name", required=True, help="Nazwa scenariusza (np. LocalAccountCreated)")
    args = parser.parse_args()

    generate_scenario(args.id, args.name)
