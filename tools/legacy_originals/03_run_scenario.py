import argparse
import subprocess
from pathlib import Path
from shared_utils import get_scenario_by_id

def run_attack(tech_id):
    folder = get_scenario_by_id(tech_id)
    if not folder:
        print(f"[!] Nie znaleziono scenariusza dla ID: {tech_id}")
        return

    script_path = folder / "attack.ps1"
    if not script_path.exists():
        print(f"[!] Brak pliku attack.ps1 w {folder.name}")
        return

    log_dir = folder / "logs"
    log_dir.mkdir(exist_ok=True)
    log_path = log_dir / "output.txt"

    print(f"[*] Uruchamianie: {script_path.name}...")
    try:
        with open(log_path, "w", encoding="utf-8") as log:
            result = subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(script_path)],
                stdout=log, stderr=log
            )
        print(f"[✓] Zakończono. Kod wyjścia: {result.returncode}. Log zapisany do: {log_path}")
    except Exception as e:
        print(f"[!] Błąd podczas uruchamiania PowerShell: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Uruchamia attack.ps1 dla danego scenariusza")
    parser.add_argument("--id", required=True, help="ID techniki (np. T1136.001)")
    args = parser.parse_args()
    run_attack(args.id)
