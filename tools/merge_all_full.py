import subprocess
import platform
import os

# Krok 1: Wyciąganie KQL z alertów
subprocess.run(["python", "tools/01_extract_kql_from_alerts.py"])

# Krok 2: Walidacja tagów
subprocess.run(["python", "tools/02_validate_tags.py"])

# Krok 3: Generowanie warstwy MITRE
subprocess.run(["python", "tools/04_generate_status.py"])
subprocess.run(["python", "tools/05_generate_report.py"])
subprocess.run(["python", "tools/06_generate_navigator_json.py"])

# Krok 4: Deploy do GitHub Pages
if platform.system() == "Windows":
    print("\n🔁 Deploying GitHub Pages...")

    # Ścieżki
    index_path = os.path.abspath("report/index.html")
    temp_path = os.path.abspath("tools/tmp_index.html")

    # Zamiana '..' na '/defender-lab-framework/alerts/'
    with open(index_path, 'r', encoding='utf-8') as infile:
        content = infile.read()

    updated_content = content.replace('href="alerts/', 'href="/defender-lab-framework/alerts/')

    with open(temp_path, 'w', encoding='utf-8') as outfile:
        outfile.write(updated_content)

    # Kopiuj zmodyfikowany index.html do report/
    subprocess.run(["copy", temp_path, "report\index.html"], shell=True)

    # Wywołaj bezpieczny deploy PowerShell
    subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", "tools/deploy-gh-pages-safe-protected.ps1"])
else:
    print("⚠️ Skipping deploy – not on Windows.")
