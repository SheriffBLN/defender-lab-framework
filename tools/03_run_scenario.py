import subprocess
import argparse
from pathlib import Path

SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "scenarios"

def run_attack(tech_id):
    for folder in SCENARIOS_DIR.iterdir():
        if tech_id.replace('.', '') in folder.name:
            script = folder / "attack.ps1"
            log_dir = folder / "logs"
            log_dir.mkdir(exist_ok=True)
            log_path = log_dir / "output.txt"

            print(f"[*] Running {script.name}...")
            with open(log_path, "w", encoding="utf-8") as log:
                result = subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", str(script)],
                                        stdout=log, stderr=log)
            print(f"[+] Output saved to {log_path}")
            return
    print(f"[!] Scenario {tech_id} not found!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", required=True, help="Technique ID (e.g. T1136.001)")
    args = parser.parse_args()
    run_attack(args.id)
