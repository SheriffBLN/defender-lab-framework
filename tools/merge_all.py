import os
import subprocess
import json

SCENARIOS_DIR = "scenarios"
TOOLS_DIR = "tools"
TAGS_REQUIRED_FIELDS = ["id", "name", "tactics", "status"]

def validate_tags():
    print("[*] Validating tags.json in all scenario folders...")
    missing = False
    for entry in os.listdir(SCENARIOS_DIR):
        path = os.path.join(SCENARIOS_DIR, entry, "tags.json")
        if not os.path.exists(path):
            print(f"  [!] MISSING: {path}")
            missing = True
            continue
        with open(path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                print(f"  [!] INVALID JSON: {path}")
                missing = True
                continue
            for field in TAGS_REQUIRED_FIELDS:
                if field not in data:
                    print(f"  [!] MISSING FIELD '{field}' in {path}")
                    missing = True
    if not missing:
        print("[+] All tags.json files are valid.")

def run_script(script_name):
    full_path = os.path.join(TOOLS_DIR, script_name)
    print(f"[*] Running {script_name}...")
    result = subprocess.run(["python", full_path])
    if result.returncode == 0:
        print(f"[+] {script_name} completed.")
    else:
        print(f"[!] {script_name} failed!")

if __name__ == "__main__":
    validate_tags()
    run_script("generate_status.py")
    run_script("generate_report.py")
