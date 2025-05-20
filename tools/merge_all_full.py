import subprocess
import platform
import os
import shutil

# Krok 1: Wyciąganie KQL z alertów
subprocess.run(["python", "tools/01_extract_kql_from_alerts.py"])

# Krok 2: Walidacja tagów
subprocess.run(["python", "tools/02_validate_tags.py"])

# Krok 3: Generowanie status.csv i raportu
subprocess.run(["python", "tools/04_generate_status.py"])
subprocess.run(["python", "tools/05_generate_report.py"])

# Krok 4: Generowanie warstwy MITRE + automatyczne dodanie tabeli logicznej
subprocess.run(["python", "tools/06_generate_navigator_json.py"])

# Krok 5: (opcjonalne) dodanie tabeli logicznej jeśli nie zintegrowano
subprocess.run(["python", "tools/09_append_matrix_table.py"])

# Krok 6: Deploy do GitHub Pages (Windows only)
if platform.system() == "Windows":
    print("\n[INFO] Deploying GitHub Pages...")

    index_path = os.path.abspath("report/index.html")
    temp_path = os.path.abspath("tools/tmp_index.html")

    try:
        with open(index_path, 'r', encoding='utf-8') as infile:
            content = infile.read()

        updated_content = content.replace('href="alerts/', 'href="/defender-lab-framework/alerts/')

        with open(temp_path, 'w', encoding='utf-8') as outfile:
            outfile.write(updated_content)

        shutil.copy(temp_path, index_path)

        subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", "tools/deploy-gh-pages-safe-protected.ps1"])
        print("[INFO] Deploy zakończony.")
    except Exception as e:
        print(f"[ERROR] Wystąpił problem z deployem: {e}")
else:
    print("[WARN] Skipping deploy – not on Windows.")