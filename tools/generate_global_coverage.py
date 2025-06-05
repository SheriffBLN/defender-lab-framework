import os
import csv
import sys
from tools.shared_utils import (
    STATUS_CSV_FIELDS,
    generate_matrix_html,
    load_alert_counts,
    print_env_diagnostics,
)

ENTERPRISE_ATTACK_CSV = "tools/enterprise_attack.csv"
LAST30_ALERTS_CSV = "tools/helpers/last30days_alerts.csv"
AUTHOR = "Defender Global Coverage"
MAPPING_DIR = "mapping/global_coverage"
REPORT_DIR = "report/global_coverage"

def load_enterprise_attack_map():
    mapping = {}
    with open(ENTERPRISE_ATTACK_CSV, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tid = row["ID"].strip().upper()
            mapping[tid] = {
                "name": row["Name"].strip(),
                "tactics": [t.strip() for t in row["Tactics"].split(",") if t.strip()],
                "description": row.get("Description", ""),
                "mitre_link": row.get("MITRE Link", "")
            }
    return mapping

def main():
    print_env_diagnostics([
        ENTERPRISE_ATTACK_CSV,
        LAST30_ALERTS_CSV
    ])

    enterprise_map = load_enterprise_attack_map()
    alert_counts = load_alert_counts(LAST30_ALERTS_CSV)

    os.makedirs(MAPPING_DIR, exist_ok=True)
    os.makedirs(REPORT_DIR, exist_ok=True)
    status_path = os.path.join(MAPPING_DIR, "status.csv")

    # 1. TYLKO techniki wyzwolone w Defenderze (ostatnie 30 dni)
    technique_counts = {tid: count for tid, count in alert_counts.items() if count > 0}

    status_rows = []
    for tid, count in sorted(technique_counts.items()):
        info = enterprise_map.get(tid, {
            "name": f"UNKNOWN_{tid}",
            "tactics": [],
            "description": "",
            "mitre_link": ""
        })
        row = {
            "Technique ID": tid,
            "Name": info["name"],
            "Tactics": ", ".join(info.get("tactics", [])),
            "Status": "Tested",
            "Linked Rule": "-",   # Brak powiązanych alertów/scenariuszy
            "Author": AUTHOR,
            "Description": info.get("description", ""),
            "MITRE Link": info.get("mitre_link", ""),
            "ChangeHistory": "-",  # Brak historii zmian w tym trybie
        }
        status_rows.append(row)

    # Zapisz status.csv (czysto poglądowo)
    with open(status_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=STATUS_CSV_FIELDS + ["ChangeHistory"])
        writer.writeheader()
        writer.writerows(status_rows)
    print(f"[✓] Plik status.csv gotowy w {status_path}")

    # Generuj matrix, heatmapę, raport HTML
    html_code = generate_matrix_html(
        status_rows,
        title="🛡️ Globalna macierz MITRE ATT&CK — tylko techniki wyzwolone w Defenderze (ostatnie 30 dni)",
        apt_folder="global_coverage",
        alert_counts=alert_counts  # tylko county dla wyzwolonych (czyli z status_rows)
    )
    out_path = os.path.join(REPORT_DIR, "index.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_code)
    print(f"[✓] Raport HTML (matrix+heatmap) zapisany do: {out_path}")

if __name__ == "__main__":
    main()
