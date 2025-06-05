import csv
import os
import json
import sys
from datetime import datetime
from collections import defaultdict

# ŚCIEŻKI
ALERTS_CSV = "tools/helpers/last30days_alerts.csv"
ENTERPRISE_CSV = "tools/enterprise_attack.csv"
OUTPUT_DIR = os.path.join("mapping", "global_coverage")
STATUS_PATH = os.path.join(OUTPUT_DIR, "status.csv")
REPORT_PATH = os.path.join("report", "global_coverage", "index.html")
AUTHOR = "Global Coverage"

# --- TACTICS_ORDER ---
TACTICS_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"
]

STATUS_BG_COLORS = {
    "Tested": "#a3e4a1",
    "Audit": "#ffe9a3",
    "Pending": "#ffb4b4",
    "Disabled": "#c3c3c3",
    "Suppressed": "#ececec"
}

BADGE_COLORS = {
    "Tested": "#43a047",
    "Audit": "#ffb300",
    "Pending": "#e53935",
    "Disabled": "#757575",
    "Suppressed": "#bdbdbd"
}

def heatmap_color(count):
    if count >= 10:
        return "#6f42c1"
    elif count >= 5:
        return "#c653ff"
    elif count >= 4:
        return "#ff704d"
    elif count >= 3:
        return "#ffa366"
    elif count >= 2:
        return "#ffd480"
    elif count >= 1:
        return "#ffffb3"
    else:
        return "#e0e0e0"

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
        {"Technique ID": "T1059.001", "Name": "PowerShell", "Tactics": "execution", "Status": "Tested", "Linked Rule": "Wyzwolona 4 razy", "Liczba wykryć": 4, "Author": AUTHOR, "Description": "Demo", "MITRE Link": "https://attack.mitre.org/techniques/T1059/001/"},
        {"Technique ID": "T1105", "Name": "Ingress Tool Transfer", "Tactics": "command-and-control", "Status": "Tested", "Linked Rule": "Wyzwolona 2 razy", "Liczba wykryć": 2, "Author": AUTHOR, "Description": "Demo", "MITRE Link": "https://attack.mitre.org/techniques/T1105/"},
        {"Technique ID": "T1566", "Name": "Phishing", "Tactics": "initial-access", "Status": "Tested", "Linked Rule": "Wyzwolona 7 razy", "Liczba wykryć": 7, "Author": AUTHOR, "Description": "Demo", "MITRE Link": "https://attack.mitre.org/techniques/T1566/"}
    ]
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(STATUS_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "Technique ID","Name","Tactics","Status","Linked Rule","Liczba wykryć","Author","Description","MITRE Link"
        ])
        writer.writeheader()
        for row in demo_status:
            writer.writerow(row)
    try:
        generate_matrix_html("global_coverage", REPORT_PATH)
        print(f"[✓] Demo matryca dostępna w {REPORT_PATH}")
    except Exception as e:
        print("[!] Błąd importu: ", e)
    input("\nNaciśnij ENTER, aby zakończyć...")
    sys.exit(0)

def generate_matrix_html(folder, outpath):
    status_path = os.path.join(OUTPUT_DIR, "status.csv")
    with open(status_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        status_rows = list(reader)

    matrix = {t: [] for t in TACTICS_ORDER}
    for r in status_rows:
        tactics = [t.strip().lower().replace(" ", "-") for t in r["Tactics"].split(",") if t.strip()]
        for t in tactics:
            if t in TACTICS_ORDER:
                matrix[t].append(r)

    # Czytelna data/godzina
    mtime = os.path.getmtime(status_path)
    gen_time = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')

    # Liczby do panelu statystyk i wykresu
    top5 = sorted(status_rows, key=lambda r: int(r.get("Liczba wykryć", 0)), reverse=True)[:5]
    top5_labels = [f"{r['Technique ID']} ({r['Name']})" for r in top5]
    top5_values = [int(r.get("Liczba wykryć", 0)) for r in top5]
    total_techs = len(status_rows)
    detected_techs = [r for r in status_rows if int(r.get("Liczba wykryć", 0)) > 0]
    percent = (len(detected_techs) / total_techs * 100) if total_techs else 0
    avg = sum(int(r.get("Liczba wykryć", 0)) for r in status_rows) / total_techs if total_techs else 0
    techs_without = [r for r in status_rows if int(r.get("Liczba wykryć", 0)) == 0]

    mini_table = '\n'.join(
        f"<tr><td>{r['Technique ID']}</td><td>{r['Name']}</td><td>{r['Liczba wykryć']}</td>"
        f"<td>{'<a href=\"' + r['MITRE Link'] + '\" target=\"_blank\">MITRE</a>' if r['MITRE Link'] else ''}</td></tr>"
        for r in top5
    )

    html = [
        "<style>",
        "body { font-family: Segoe UI, Arial, sans-serif; }",
        ".container { max-width:1180px; margin:0 auto; }",
        ".matrix-table { border-collapse:collapse; width:100%; margin-bottom:28px; }",
        ".matrix-table th { background:#dbeafe; color:#1e293b; padding:7px 0; font-size:1.07em; border:1px solid #e3e3e3; }",
        ".matrix-table td { vertical-align:top; border:1px solid #e3e3e3; min-width:94px; padding:2px; }",
        ".matrix-technique { border-radius:7px; box-shadow:1px 2px 8px #e6e6e6; margin:7px 0; padding:7px 7px 5px 7px; font-size:.97em; font-weight:500; background:#fff; }",
        ".badge { padding:2px 12px 2px 12px; border-radius:8px; color:#fff; font-size:.92em; font-weight:700; letter-spacing:.05em; display:inline-block; }",
        ".badge-Tested { background:%s; }" % BADGE_COLORS["Tested"],
        ".badge-Audit { background:%s; color:#333 !important; }" % BADGE_COLORS["Audit"],
        ".badge-Pending { background:%s; }" % BADGE_COLORS["Pending"],
        ".badge-Disabled { background:%s; color:#222 !important; }" % BADGE_COLORS["Disabled"],
        ".badge-Suppressed { background:%s; color:#222 !important; }" % BADGE_COLORS["Suppressed"],
        "</style>",
        "<body style='font-family:Segoe UI,Arial,sans-serif;'>",
        '<div class="container">',
        f'<h1>🛡️ Global Coverage Matrix</h1>',
        f'<div style="margin:10px 0 18px 0; font-size:1.18em;">Macierz MITRE ATT&CK – globalna pokrycie detekcji</div>',
        f'<p style="color:#557;">Wygenerowano: {gen_time}</p>',
        '<h2>Status macierzy (Tested / Audit / Pending)</h2>',
        '<table class="matrix-table"><tr>'
    ]
    for tactic in TACTICS_ORDER:
        html.append(f"<th>{tactic}</th>")
    html.append("</tr><tr>")
    for tactic in TACTICS_ORDER:
        html.append("<td>")
        for row in matrix.get(tactic, []):
            status = row["Status"]
            bg = STATUS_BG_COLORS.get(status, "#fff")
            html.append(
                f'<div class="matrix-technique" style="background:{bg};">'
                f'<b>{row["Technique ID"]}</b><br>{row["Name"]}'
                f'<br><span class="badge badge-{status}">{status}</span>'
                f'<br><span style="font-size:0.95em; color:#565;">{row.get("Linked Rule", "-")}</span>'
                '</div>'
            )
        html.append("</td>")
    html.append("</tr></table>")

    # --- DRUGA MATRYCA: HEATMAPA ---
    tech_counts = {}
    for r in status_rows:
        try:
            tech_counts[r["Technique ID"]] = int(r.get("Liczba wykryć") or 0)
        except:
            tech_counts[r["Technique ID"]] = 0

    html.append('<h2>🔥 Heatmapa wyzwolonych technik</h2>')
    html.append('<table class="matrix-table"><tr>')
    for tactic in TACTICS_ORDER:
        html.append(f"<th>{tactic}</th>")
    html.append("</tr><tr>")
    for tactic in TACTICS_ORDER:
        html.append("<td>")
        for row in matrix.get(tactic, []):
            tid = row["Technique ID"]
            count = tech_counts.get(tid, 0)
            color = heatmap_color(count)
            html.append(
                f'<div class="matrix-technique" style="background:{color};border:1.5px solid #b6b6b6;">'
                f'<b>{tid}</b><br>{row["Name"]}'
                f'<div style="margin-top:5px;">'
                f'<span style="font-size:1.09em;font-weight:600;color:#d7263d;">{"🔥" if count else "–"}</span> '
                f'<span style="font-size:1.04em;">{count} alertów</span>'
                '</div></div>'
            )
        if not matrix.get(tactic, []):
            html.append('<div class="matrix-technique" style="background:#ececec;">–</div>')
        html.append("</td>")
    html.append("</tr></table>")
    html.append("""
    <div style="margin-top:12px; font-size:1.01em; color:#555;">
        <b>Legenda kolorów:</b>
        <span style="background:#ffffb3; padding:2px 8px; margin-right:8px;">1</span>
        <span style="background:#ffd480; padding:2px 8px; margin-right:8px;">2</span>
        <span style="background:#ffa366; padding:2px 8px; margin-right:8px;">3</span>
        <span style="background:#ff704d; padding:2px 8px; margin-right:8px;">4</span>
        <span style="background:#c653ff; padding:2px 8px; margin-right:8px;">5+</span>
        <span style="background:#6f42c1; padding:2px 8px; margin-right:8px;">10+</span>
    </div>
    """)

    # === PANEL STATYSTYK I WYKRESÓW ===
    html.append(f"""
    <div class="panel" style="background:#fff; border-radius:12px; box-shadow:0 2px 13px #dde3ef66; padding:28px 32px; margin-top:44px;">
    <ul class="stat-list" style="font-size:1.09em; margin-bottom:20px;">
    <li><b>Technik z co najmniej 1 alertem:</b> {len(detected_techs)} / {total_techs} ({percent:.1f}%)</li>
    <li><b>Najczęściej wykrywane techniki (Top 5):</b> {', '.join(f'{r['Technique ID']} ({r['Name']}, {r['Liczba wykryć']} razy)' for r in top5)}</li>
    <li><b>Techniki bez żadnej detekcji:</b> {', '.join(f"{r['Technique ID']} ({r['Name']})" for r in techs_without) if techs_without else 'Brak'}</li>
    <li><b>Średnia liczba alertów na technikę:</b> {avg:.2f}</li>
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
    {mini_table}
    </table>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
    document.addEventListener("DOMContentLoaded", function() {{
        var ctx = document.getElementById('top5Chart').getContext('2d');
        new Chart(ctx, {{
            type: 'bar',
            data: {{
                labels: {json.dumps(top5_labels)},
                datasets: [{{
                    label: 'Liczba wykryć',
                    data: {json.dumps(top5_values)},
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
    """)

    # --- tabela statusów ---
    html.append('<h2>📊 Tabela statusów</h2>')
    html.append('<table class="matrix-table"><tr><th>Technique ID</th><th>Name</th><th>Tactics</th><th>Status</th><th>Linked Rule</th><th>Liczba wykryć</th><th>Author</th><th>Description</th><th>MITRE Link</th></tr>')
    for row in status_rows:
        status = row["Status"]
        html.append(
            f"<tr style='background:#fff;'>" +
            "".join(f"<td>{row.get(c,'')}</td>" for c in ["Technique ID","Name","Tactics","Status","Linked Rule","Liczba wykryć","Author","Description","MITRE Link"]) +
            "</tr>"
        )
    html.append("</table>")
    html.append("</div></body></html>")
    with open(outpath, "w", encoding="utf-8") as f:
        f.write("\n".join(html))

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
            "Technique ID","Name","Tactics","Status","Linked Rule","Liczba wykryć","Author","Description","MITRE Link"
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
                "Liczba wykryć": count,
                "Author": AUTHOR,
                "Description": info.get("description", ""),
                "MITRE Link": info.get("mitre_link", "")
            })

    print(f"[✓] Wygenerowano mapping/global_coverage/status.csv")

    # 4. Generuj macierz MITRE (macierz + heatmapa + panele)
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    generate_matrix_html("global_coverage", REPORT_PATH)
    print(f"[✓] Wygenerowano raport MITRE matrix z heatmapą i statystykami: {REPORT_PATH}")

if __name__ == "__main__":
    main()
