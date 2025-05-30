import csv
import os
import json
import sys

# ŚCIEŻKI
ALERTS_CSV = "tools/helpers/last30days_alerts.csv"
ENTERPRISE_CSV = "tools/enterprise_attack.csv"
OUTPUT_DIR = os.path.join("mapping", "global_coverage")
STATUS_PATH = os.path.join(OUTPUT_DIR, "status.csv")
REPORT_PATH = os.path.join("report", "global_coverage", "index.html")
AUTHOR = "Global Coverage"

def check_files_exist():
    print("\n[DIAGNOSTYKA] Sprawdzam środowisko:")
    print(f"Python: {sys.version}")
    print(f"CWD: {os.getcwd()}")
    missing = []
    for path in [ALERTS_CSV, ENTERPRISE_CSV]:
        print(f" - {path} ...", end="")
        if not os.path.exists(path):
            print("❌ NIE ZNALEZIONO")
            missing.append(path)
        else:
            try:
                with open(path, encoding="utf-8") as f:
                    head = f.readline().strip()
                    print(f" ✅ OK (nagłówki: {head[:80]})")
            except Exception as e:
                print(f" ⚠️ Problem: {e}")
                missing.append(path)
    return missing

def run_demo_mode():
    print("\n[DEMO MODE] Uruchamiam przykładową matrycę i heatmapę na danych demo.")
    demo_status = [
        {"Technique ID": "T1059.001", "Name": "PowerShell", "Tactics": "execution", "Status": "Tested", "Linked Rule": "Wyzwolona 4 razy", "Author": AUTHOR, "Description": "Demo", "MITRE Link": "https://attack.mitre.org/techniques/T1059/001/"},
        {"Technique ID": "T1105", "Name": "Ingress Tool Transfer", "Tactics": "command-and-control", "Status": "Tested", "Linked Rule": "Wyzwolona 2 razy", "Author": AUTHOR, "Description": "Demo", "MITRE Link": "https://attack.mitre.org/techniques/T1105/"},
        {"Technique ID": "T1566", "Name": "Phishing", "Tactics": "initial-access", "Status": "Tested", "Linked Rule": "Wyzwolona 7 razy", "Author": AUTHOR, "Description": "Demo", "MITRE Link": "https://attack.mitre.org/techniques/T1566/"}
    ]
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(STATUS_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "Technique ID","Name","Tactics","Status","Linked Rule","Author","Description","MITRE Link"
        ])
        writer.writeheader()
        for row in demo_status:
            writer.writerow(row)
    # Generuj matrycę HTML
    try:
        from defender_lab import generate_matrix_html
        os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
        generate_matrix_html("global_coverage", REPORT_PATH, apt_mode=True)
        print(f"[✓] Demo matryca dostępna w {REPORT_PATH}")
    except Exception as e:
        print("[!] Błąd importu: ", e)
    input("\nNaciśnij ENTER, aby zakończyć...")
    sys.exit(0)

def main():
    print("\n=== Global Coverage Matrix (przyjazna obsługa plików) ===")
    missing = check_files_exist()
    if missing:
        print("\n[!] Brak wymaganych plików: ", ", ".join(missing))
        demo = input("Czy uruchomić DEMO MODE? (t/n): ").strip().lower()
        if demo == "t":
            run_demo_mode()
        else:
            print("\nPrzerwano. Uzupełnij brakujące pliki i spróbuj ponownie.")
            sys.exit(1)

    # 1. Zbierz statystyki z alertów
    technique_counts = {}
    with open(ALERTS_CSV, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tid = row.get("Technique ID") or row.get("technique_id") or row.get("AttackTechniques")
            if tid:
                tid = tid.strip().upper()
                technique_counts[tid] = technique_counts.get(tid, 0) + int(row.get("Count", 1))

    # 2. Wczytaj enterprise_attack.csv (dane technik)
    enterprise_map = {}
    with open(ENTERPRISE_CSV, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tid = row["ID"].strip().upper()
            enterprise_map[tid] = {
                "name": row.get("Name", tid),
                "tactics": row.get("Tactics", ""),
                "description": row.get("Description", ""),
                "mitre_link": row.get("MITRE Link", "")
            }

    # 3. Utwórz status.csv
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(STATUS_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "Technique ID","Name","Tactics","Status","Linked Rule","Author","Description","MITRE Link"
        ])
        writer.writeheader()
        for tid, count in technique_counts.items():
            info = enterprise_map.get(tid, {})
            writer.writerow({
                "Technique ID": tid,
                "Name": info.get("name", tid),
                "Tactics": info.get("tactics", ""),
                "Status": "Tested" if count > 0 else "Pending",
                "Linked Rule": f"Wyzwolona {count} razy",
                "Author": AUTHOR,
                "Description": info.get("description", ""),
                "MITRE Link": info.get("mitre_link", "")
            })

    print(f"[✓] Wygenerowano mapping/global_coverage/status.csv")

    # 4. Generuj macierz MITRE (macierz + heatmapa) jak w defender_lab.py
    try:
        from defender_lab import generate_matrix_html
    except ImportError:
        print("Błąd: nie mogę zaimportować generate_matrix_html z defender_lab.py")
        sys.exit(1)

    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    generate_matrix_html("global_coverage", REPORT_PATH, apt_mode=True)
    print(f"[✓] Wygenerowano raport MITRE matrix z heatmapą: {REPORT_PATH}")

    # 5. Panel statystyk + wykres (dołączony na końcu HTML)
    with open(REPORT_PATH, "r", encoding="utf-8") as f:
        html = f.read()

    # Zbierz dane do statystyk
    summary_rows = []
    for tid, count in technique_counts.items():
        info = enterprise_map.get(tid, {})
        summary_rows.append({
            "Technique ID": tid,
            "Name": info.get("name", tid),
            "Detection Count": count,
            "MITRE Link": info.get("mitre_link", "")
        })

    summary_rows.sort(key=lambda x: x["Detection Count"], reverse=True)
    top5 = summary_rows[:5]
    num_techniques = len(summary_rows)
    num_with_alerts = sum(1 for r in summary_rows if r["Detection Count"] > 0)
    techniques_without_alerts = [r["Technique ID"] for r in summary_rows if r["Detection Count"] == 0]
    avg_alerts = sum(r["Detection Count"] for r in summary_rows) / num_techniques if num_techniques else 0
    percent_coverage = 100.0 * num_with_alerts / num_techniques if num_techniques else 0

    panel = f"""
    <div class="panel" style="background:#fff; border-radius:12px; box-shadow:0 2px 13px #dde3ef66; padding:28px 32px; margin-top:44px;">
    <ul class="stat-list" style="font-size:1.09em; margin-bottom:20px;">
    <li><b>Technik z co najmniej 1 alertem:</b> {num_with_alerts} / {num_techniques} ({percent_coverage:.1f}%)</li>
    <li><b>Najczęściej wykrywane techniki (Top 5):</b> {', '.join(f'{row["Technique ID"]} ({row["Name"]}, {row["Detection Count"]} razy)' for row in top5)}</li>
    <li><b>Techniki bez żadnej detekcji:</b> {", ".join(techniques_without_alerts) if techniques_without_alerts else "Brak"}</li>
    <li><b>Średnia liczba alertów na technikę:</b> {avg_alerts:.2f}</li>
    </ul>
    <div class="disclaimer" style="color:#888; font-size:.99em; margin-top:15px;">To jest widok statystyczny. Liczba wykryć = suma alertów dla danej techniki, nie konkretna reguła.<br>
    Aby zobaczyć szczegóły (np. scenariusze czy reguły), przejdź do widoku APT lub pojedynczej techniki.</div>
    </div>
    <div class="chart-box" style="margin:38px 0 20px 0; background:#f7fafd; padding:22px; border-radius:13px;">
    <h2 style="margin-top:0;">🔝 Top 5 najczęściej wykrywanych technik</h2>
    <canvas id="top5Chart" width="600" height="260"></canvas>
    </div>
    <table class="mini-table" style="margin-top:30px; border-collapse:collapse; width:80%; font-size:1.02em; background:#fff;">
    <tr><th>Technique ID</th><th>Name</th><th>Liczba detekcji</th><th>MITRE</th></tr>
    """
    for row in top5:
        mitre = row['MITRE Link']
        mitre_display = f'<a href="{mitre}" target="_blank">MITRE</a>' if mitre else ''
        panel += (
            f"<tr>"
            f"<td>{row['Technique ID']}</td>"
            f"<td>{row['Name']}</td>"
            f"<td>{row['Detection Count']}</td>"
            f"<td>{mitre_display}</td>"
            f"</tr>"
        )
    panel += "</table>"
    panel += f"""
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
    document.addEventListener("DOMContentLoaded", function() {{
        var ctx = document.getElementById('top5Chart').getContext('2d');
        new Chart(ctx, {{
            type: 'bar',
            data: {{
                labels: {json.dumps([f"{row['Technique ID']} ({row['Name']})" for row in top5])},
                datasets: [{{
                    label: 'Liczba wykryć',
                    data: {json.dumps([row['Detection Count'] for row in top5])},
                    backgroundColor: [
                        'rgba(64, 192, 87, 0.85)',
                        'rgba(72, 123, 255, 0.85)',
                        'rgba(255, 212, 67, 0.85)',
                        'rgba(255, 107, 107, 0.85)',
                        'rgba(198, 83, 255, 0.85)'
                    ],
                    borderRadius: 10,
                    borderWidth: 2
                }}]
            }},
            options: {{
                indexAxis: 'y',
                responsive: false,
                plugins: {{
                    legend: {{ display: false }},
                    title: {{ display: false }}
                }},
                scales: {{
                    x: {{ beginAtZero: true, ticks: {{ precision:0 }} }},
                    y: {{ beginAtZero: true }}
                }}
            }}
        }});
    }});
    </script>
    """

    # Dołącz panel POD główną zawartością (tuż przed </div></body></html>)
    insert_pos = html.rfind('</div></body></html>')
    if insert_pos == -1:
        insert_pos = len(html)
    html = html[:insert_pos] + panel + html[insert_pos:]

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[✓] Wygenerowano raport końcowy z matrycą i statystyką: {REPORT_PATH}")

if __name__ == "__main__":
    main()
