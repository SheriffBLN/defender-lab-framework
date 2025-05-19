import subprocess

scripts = [
    "01_extract_kql_from_alerts.py",
    "02_validate_tags.py",
    "04_generate_status.py",
    "05_generate_report.py",
    "06_generate_navigator_json.py"
]

def run_pipeline():
    for script in scripts:
        print(f"[*] Uruchamianie {script}...")
        result = subprocess.run(["python", f"tools/{script}"])
        if result.returncode != 0:
            print(f"[!] Błąd w {script} (kod: {result.returncode})")
            break
        else:
            print(f"[✓] {script} zakończony pomyślnie\n")

    print("[✓] Pipeline zakończony.")

if __name__ == "__main__":
    run_pipeline()
