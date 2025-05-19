import subprocess

scripts = [
    "01_extract_kql_from_alerts.py",
    "02_validate_tags.py",
    "04_generate_status.py",
    "05_generate_report.py",
    "06_generate_navigator_json.py"
]

for script in scripts:
    print(f"[*] Running {script}...")
    subprocess.run(["python", f"tools/{script}"])
