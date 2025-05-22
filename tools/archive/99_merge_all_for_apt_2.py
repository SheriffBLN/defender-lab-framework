import os
import json
import csv
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path

STATUS_COLORS = {
    "Tested": "#d4edda",
    "Audit": "#fff3cd",
    "Pending": "#f8d7da"
}

def print_intro():
    print("🛡️ Defender Lab Framework – Tryb wejściowy")

def validate_techniques(input_str, attack_data):
    wrong_format = []
    not_in_db = []
    techniques = []
    for tid in input_str.split(","):
        tid = tid.strip().upper()
        if not tid:
            continue
        if not (tid.startswith("T") and (tid[1:].isdigit() or "." in tid)):
            wrong_format.append(tid)
        elif tid not in attack_data:
            not_in_db.append(tid)
        else:
            techniques.append(tid)
    return techniques, wrong_format, not_in_db

def step_00a_input():
    print_intro()
    # Wczytaj bazę technik
    csv_path = os.path.join("tools", "enterprise_attack.csv")
    attack_data = {}
    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            attack_data[row["ID"].strip().upper()] = {
                "name": row["Name"].strip(),
                "tactics": [t.strip() for t in row["Tactics"].split(",") if t.strip()]
            }
    while True:
        technique_input = input("Podaj ID technik (np. T1059,T1566.001): ").strip()
        techniques, wrong_format, not_in_db = validate_techniques(technique_input, attack_data)
        if wrong_format or not_in_db or not techniques:
            print("❗ Znaleziono błędy w podanych technikach:")
            if wrong_format:
                print(f"- {', '.join(wrong_format)}: niepoprawny format (powinno być np. T1059 lub T1566.001)")
            if not_in_db:
                print(f"- {', '.join(not_in_db)}: nie istnieje w enterprise_attack.csv")
            print("Spróbuj ponownie.")
        else:
            break
    # Dodaj możliwość własnej nazwy folderu/scenariusza, jak ktoś chce alerty o różnych nazwach
    if len(techniques) > 1:
        apt_mode = True
        apt_name = input("Podaj nazwę grupy APT (np. APT29): ").strip() or "APT"
    else:
        apt_mode = False
        apt_name = "SingleTechnique"
    # Własny alias dla alertu/scenariusza (opcjonalnie)
    custom_folders = {}
    for tid in techniques:
        folder = input(f"Podaj własną nazwę folderu dla alertu/scenariusza ({tid}) [ENTER=domyślna]: ").strip()
        if folder:
            custom_folders[tid] = folder
    # Status
    while True:
        status = input("Podaj status (Pending/Audit/Tested): ").strip().capitalize()
        if status not in ("Pending", "Audit", "Tested"):
            print("❗ Wprowadź poprawny status: Pending / Audit / Tested.")
        else:
            break
    # Autor
    while True:
        author = input("Podaj autora: ").strip()
        if not author:
            print("❗ Autor nie może być pusty.")
        else:
            break
    enriched = []
    for tid in techniques:
        info = attack_data.get(tid, {"name": "UNKNOWN", "tactics": []})
        enriched.append({
            "technique_id": tid,
            "technique_name": info["name"],
            "tactics": info["tactics"],
            "custom_folder": custom_folders.get(tid) or tid
        })
    return {
        "techniques": enriched,
        "apt_mode": apt_mode,
        "apt_name": apt_name or "SingleTechnique",
        "status": status,
        "author": author
    }

def step_00b_create_structure(context):
    print("[00b] Tworzenie struktury folderów...")
    bases = ["alerts", "hunting", "mapping", "scenarios", "report"]
    apt = context["apt_name"]
    for base in bases:
        base_path = os.path.join(base, apt)
        os.makedirs(base_path, exist_ok=True)
        if base != "report":
            for tech in context["techniques"]:
                folder = tech.get("custom_folder", tech["technique_id"])
                os.makedirs(os.path.join(base_path, folder), exist_ok=True)
    print("[00b] Struktura utworzona.")

def step_01_generate_alerts(context):
    print("[01] Generowanie plików alertów z helpers/report_template.md ...")
    template_path = "tools/helpers/report_template.md"
    with open(template_path, "r", encoding="utf-8") as f:
        template = f.read()
    apt = context["apt_name"]
    for tech in context["techniques"]:
        folder = tech.get("custom_folder", tech["technique_id"])
        out = os.path.join("alerts", apt, folder, f"{tech['technique_id']}_alert.md")
        kql_path = os.path.join("hunting", apt, folder, f"{tech['technique_id']}.kql")
        kql_queries = ""
        if os.path.exists(kql_path):
            with open(kql_path, encoding='utf-8') as kf:
                kql_queries = kf.read().strip()
        with open(out, "w", encoding='utf-8') as f:
            f.write(template.format(
                technique_id=tech['technique_id'],
                technique_name=tech["technique_name"],
                tactics=", ".join(tech["tactics"]),
                status=context["status"],
                author=context["author"],
                kql_queries=kql_queries,
                triage_tips="",  # Dodaj w przyszłości jeśli chcesz
            ))
    print("[01] Alerty wygenerowane.")

def step_02_insert_kql(context):
    print("[02] Wstawianie KQL do alertów... [pomijane – KQL jest już uwzględniony wyżej jeśli istnieje]")
    # KQL jest już dołączany w step_01_generate_alerts (nic więcej nie trzeba robić)

def step_03_generate_scenarios(context):
    print("[03] Generowanie scenariuszy testowych...")
    apt = context["apt_name"]
    for tech in context["techniques"]:
        folder = tech.get("custom_folder", tech["technique_id"])
        scen = os.path.join("scenarios", apt, folder, f"{tech['technique_id']}_scenario.md")
        tags = os.path.join("scenarios", apt, folder, "tags.json")
        content = (
            f"# Scenariusz testowy – {tech['technique_id']}\n\n"
            f"## Symulacja ataku\nOpis: Symulacja techniki {tech['technique_id']} – {tech['technique_name']}.\n\n"
            "## Detekcja\n"
            f"Oczekiwany alert: `{tech['technique_id']}_alert.md`\n\n"
            "## Oczekiwany efekt\n"
            f"Technika powinna zostać wykryta. Taktyki: {', '.join(tech['tactics'])}.\n"
        )
        with open(scen, "w", encoding='utf-8') as f:
            f.write(content)
        tag_data = {
            "id": tech["technique_id"],
            "name": tech['technique_name'],
            "tactics": tech['tactics'],
            "status": context['status'],
            "linked_rule": f"alerts/{apt}/{folder}/{tech['technique_id']}_alert.md"
        }
        with open(tags, "w", encoding='utf-8') as f:
            json.dump(tag_data, f, indent=4)
    print("[03] Scenariusze i tags.json wygenerowane.")

def step_04_generate_mitre_layer(context):
    print("[04] Tworzenie warstwy MITRE Navigator...")
    apt = context["apt_name"]
    techniques = [{"techniqueID": t['technique_id'], "score": 1} for t in context['techniques']]
    layer = {
        "name": f"{apt} – Lab Coverage",
        "version": "4.6",
        "domain": "enterprise-attack",
        "techniques": techniques
    }
    out = os.path.join("mapping", apt, "layer.json")
    with open(out, "w", encoding='utf-8') as f:
        json.dump(layer, f, indent=4)
    print(f"[04] Warstwa zapisana: {out}")

def step_04a_generate_status_csv(context):
    print("[04a] Generowanie status.csv...")
    from pathlib import Path
    apt = context['apt_name']
    rows = []
    scenario_base = Path("scenarios") / apt
    dirs = [d for d in scenario_base.iterdir() if d.is_dir()]
    for folder in dirs:
        tags_file = folder / "tags.json"
        if not tags_file.exists():
            continue
        data = json.loads(tags_file.read_text(encoding='utf-8'))
        rows.append([
            data.get('id',''),
            data.get('name',''),
            ", ".join(data.get('tactics',[])),
            data.get('status',''),
            data.get('linked_rule','')
        ])
    out_csv = Path("mapping") / apt / "status.csv"
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(["Technique ID","Name","Tactics","Status","Linked Rule"])
        w.writerows(rows)
    print(f"[04a] Zapisano {len(rows)} rekordów do {out_csv}")

def step_05_generate_html_report(context):
    print("[05] Tworzenie raportu HTML...")
    csv_path, apt = get_csv_path(context)
    output_path = os.path.join("report", apt, "index.html")
    if not Path(csv_path).exists():
        print(f"[!] Brak pliku status.csv pod: {csv_path}")
        return
    with open(csv_path, encoding='utf-8') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    if not rows:
        print("[!] Plik status.csv jest pusty.")
        return
    total = len(rows)
    status_counts = Counter(r['Status'] for r in rows)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tactic_groups = defaultdict(list)
    for r in rows:
        for t in r['Tactics'].split(','):
            tac = t.strip()
            if tac:
                tactic_groups[tac].append(r)
    html = [
        '<!DOCTYPE html>', '<html>', '<head>', '  <meta charset="UTF-8">',
        f'  <title>Raport {apt}</title>', '  <style>',
        '    body { font-family: Arial, sans-serif; padding:20px; }',
        '    h1 { border-bottom:2px solid #333; }',
        '    table { width:100%; border-collapse: collapse; margin-bottom:20px; }',
        '    th, td { border:1px solid #999; padding:8px; text-align:left; }',
        '    th { background:#eee; }', '    ul { margin-bottom:20px; }',
        '  </style>', '</head>', '<body>',
        f'  <h1>Raport: {apt}</h1>', f'  <p>Wygenerowano: {now}</p>',
        f'  <p>Łączna liczba technik: {total}</p>', '  <ul>'
    ]
    for status, count in status_counts.items():
        html.append(f'    <li>{status}: {count}</li>')
    html.append('  </ul>')
    for tactic, group in sorted(tactic_groups.items()):
        html.append(f"  <h2>{tactic}</h2>")
        html.append('  <table>')
        html.append('    <tr><th>Technique ID</th><th>Name</th><th>Status</th><th>Linked Rule</th></tr>')
        for r in group:
            bg = STATUS_COLORS.get(r['Status'], '#ffffff')
            link = r['Linked Rule']
            html.append(
                f"    <tr style='background:{bg};'>"
                f"<td>{r['Technique ID']}</td>"
                f"<td>{r['Name']}</td>"
                f"<td>{r['Status']}</td>"
                f"<td><a href='{link}' target='_blank'>{link}</a></td>"
                "</tr>"
            )
        html.append('  </table>')
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(html))
    print(f"[✓] Raport zapisany do: {output_path}")

def get_csv_path(context):
    apt = context["apt_name"] if context["apt_mode"] else "SingleTechnique"
    return os.path.join("mapping", apt, "status.csv"), apt

def step_06_add_matrix_table(context):
    print("[06] Dodawanie macierzy ATT&CK – tabela logiczna...")
    TACTICS_ORDER = [
        "initial-access", "execution", "persistence", "privilege-escalation",
        "defense-evasion", "credential-access", "discovery", "lateral-movement",
        "collection", "command-and-control", "exfiltration", "impact"
    ]
    apt = context['apt_name']
    csv_file = os.path.join("mapping", apt, "status.csv")
    html_file = os.path.join("report", apt, "index.html")
    if not os.path.exists(csv_file) or not os.path.exists(html_file):
        print("[!] Brak CSV lub HTML")
        return
    rows = list(csv.DictReader(open(csv_file, encoding='utf-8')))
    matrix = {t: [] for t in TACTICS_ORDER}
    for r in rows:
        for t in r['Tactics'].split(','):
            key = t.strip().lower()
            if key in matrix:
                bg = STATUS_COLORS.get(r['Status'], '#ffffff')
                cell = f"<td style='background:{bg};'>{r['Technique ID']}<br>{r['Name']}<br>[{r['Status']}]</td>"
                matrix[key].append(cell)
    section = ['<hr>', '<h2>🧭 Macierz ATT&CK – tabela logiczna</h2>', '<table border="1" cellspacing="0" cellpadding="6"><tr>']
    for t in TACTICS_ORDER:
        section.append(f"<th>{t}</th>")
    section.append("</tr><tr>")
    for t in TACTICS_ORDER:
        section.append("".join(matrix[t]) or "<td></td>")
    section.append("</tr></table>")
    with open(html_file, "a", encoding='utf-8') as f:
        f.write("\n" + "\n".join(section))
    print(f"[✓] Macierz ATT&CK została dodana do raportu {html_file}")

def main():
    ctx = step_00a_input()
    step_00b_create_structure(ctx)
    step_01_generate_alerts(ctx)
    step_02_insert_kql(ctx)
    step_03_generate_scenarios(ctx)
    step_04_generate_mitre_layer(ctx)
    step_04a_generate_status_csv(ctx)
    step_05_generate_html_report(ctx)
    step_06_add_matrix_table(ctx)
    print("\n🎉 Wszystkie kroki zakończone!")

if __name__ == "__main__":
    main()
