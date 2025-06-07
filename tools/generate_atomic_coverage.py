import os
import csv
import re
from datetime import datetime
from tools.shared_utils import (
    TACTICS_ORDER, MITRE_TACTICS, format_datetime, generate_matrix_html, ensure_dir, safe_filename
)

MAPPING_DIR = "mapping"
ART_REPO_DIR = "atomic_red_team_repo/atomics"
REPORT_DIR = "report/atomic_coverage"
ATOMIC_SCEN_DIR = "scenarios/atomic_tests"

def get_atomic_tests_for_tid(tid):
    art_md = os.path.join(ART_REPO_DIR, tid, f"{tid}.md")
    if not os.path.exists(art_md):
        return []
    with open(art_md, encoding="utf-8") as f:
        content = f.read()
    atomic_tests = []
    for block in re.findall(r"(#{2,4} Atomic Test.*?)(?=\n#{2,4} Atomic Test|\Z)", content, re.DOTALL):
        match = re.search(r"\*\*Supported Platforms:\*\* ([^\n]+)", block)
        if not (match and "Windows" in match.group(1)):
            continue
        title_match = re.match(r"#{2,4} Atomic Test\s*#?\d+\s*-\s*(.+)", block)
        title = title_match.group(1).strip() if title_match else "Brak tytułu"
        desc_match = re.search(r"\*\*Description:\*\*([^\n]+)", block)
        desc = desc_match.group(1).strip() if desc_match else ""
        cmd_blocks = re.findall(r"#### Attack Commands:.*?```(\w+)\n(.*?)```", block, re.DOTALL)
        cleanup_blocks = re.findall(r"#### Cleanup Commands:.*?```(\w+)\n(.*?)```", block, re.DOTALL)
        atomic_tests.append({
            "title": title,
            "desc": desc,
            "scripts": [(stype, code.strip()) for stype, code in cmd_blocks],
            "cleanup": [(stype, code.strip()) for stype, code in cleanup_blocks],
            "raw": block
        })
    return atomic_tests

def wybierz_status_csv():
    all_folders = [f for f in os.listdir(MAPPING_DIR) if os.path.isdir(os.path.join(MAPPING_DIR, f))]
    print("Dostępne mappingi/scenariusze:")
    for idx, f in enumerate(all_folders):
        print(f"{idx+1}. {f}")
    nr = input("Wybierz numer mappingu (ENTER=SingleTechnique): ").strip()
    if not nr:
        mapping = "SingleTechnique"
    else:
        mapping = all_folders[int(nr)-1]
    status_csv = os.path.join(MAPPING_DIR, mapping, "status.csv")
    if not os.path.exists(status_csv):
        print(f"Brak pliku: {status_csv}")
        exit(1)
    print(f"Wybrano mapping: {mapping}")
    return mapping, status_csv

def atomic_coverage_matrix():
    mapping, status_csv = wybierz_status_csv()
    now = format_datetime()
    with open(status_csv, encoding="utf-8") as f:
        status_rows = list(csv.DictReader(f))

    matrix_status = []
    test_status = []

    for row in status_rows:
        tid = row["Technique ID"].strip().upper()
        tactics = [t.strip() for t in row["Tactics"].split(",") if t.strip()]
        tests = get_atomic_tests_for_tid(tid)
        if tests:
            badge = f"ART-exist ({len(tests)})"
            matrix_status.append({
                "Technique ID": tid,
                "Name": row["Name"],
                "Tactics": ", ".join(tactics),
                "Status": badge,
                "Tooltip": f"{len(tests)} test(ów) Atomic Red Team"
            })
            for t in tests:
                test_status.append({
                    "Technique ID": tid,
                    "Name": row["Name"],
                    "Tactics": ", ".join(tactics),
                    "Status": "ART-exist",
                    "Test Title": t["title"],
                    "Scripts": "; ".join([stype for stype, _ in t["scripts"]]),
                })
        else:
            matrix_status.append({
                "Technique ID": tid,
                "Name": row["Name"],
                "Tactics": ", ".join(tactics),
                "Status": "no-ART",
                "Tooltip": "Brak testów Atomic Red Team"
            })

    html = [
        "<style>",
        "body { font-family: Segoe UI, Arial, sans-serif; }",
        ".container { max-width:1200px; margin:0 auto; }",
        ".matrix-table { border-collapse:collapse; width:100%; margin-bottom:28px; }",
        ".matrix-table th { background:#dbeafe; color:#1e293b; padding:7px 0; font-size:1.07em; border:1px solid #e3e3e3; }",
        ".matrix-table td { vertical-align:top; border:1px solid #e3e3e3; min-width:94px; padding:2px; }",
        ".matrix-technique { border-radius:7px; box-shadow:1px 2px 8px #e6e6e6; margin:7px 0; padding:7px 7px 5px 7px; font-size:.97em; font-weight:500; background:#fff; }",
        ".badge { padding:2px 12px 2px 12px; border-radius:8px; color:#fff; font-size:.92em; font-weight:700; letter-spacing:.05em; display:inline-block; }",
        ".badge-ART-exist { background:#3fa4fa; }",
        ".badge-no-ART { background:#aaa; }",
        "</style>",
        '<div class="container">',
        f'<h2 style="margin-bottom:12px;">Atomic Coverage Matrix</h2>',
        f'<div style="font-size:0.99em;color:#888;margin-bottom:10px;">Generowano: {now} | Mapping: <code>{mapping}</code></div>',
        "<table class='matrix-table'><tr class='header-row'>"
    ]
    for t in TACTICS_ORDER:
        label, ta_id = MITRE_TACTICS.get(t, (t.title(), ""))
        html.append(f'<th>{label}<br/><span style="font-size:0.84em;color:#9bb;">{ta_id}</span></th>')
    html.append("</tr><tr>")
    for tactic in TACTICS_ORDER:
        html.append("<td>")
        for row in matrix_status:
            tactics = [t.strip().lower().replace(" ", "-") for t in row["Tactics"].split(",") if t.strip()]
            if tactic in tactics:
                status = row["Status"]
                tid = row["Technique ID"]
                name = row["Name"]
                tooltip = row.get("Tooltip") or ""
                if status.startswith("ART-exist"):
                    bg = "#eaf4ff"
                    badge = f'<span class="badge badge-ART-exist">{status}</span>'
                elif status.startswith("no-ART"):
                    bg = "#ececec"
                    badge = f'<span class="badge badge-no-ART">{status}</span>'
                else:
                    bg = "#fff"
                    badge = f'<span class="badge">{status}</span>'
                html.append(
                    f'<div class="matrix-technique" style="background:{bg};" title="{tooltip}">'
                    f'<b>{tid}</b><br>{name}'
                    f'<br>{badge}'
                    '</div>'
                )
        html.append("</td>")
    html.append("</tr></table>")

    html.append('<h3>Lista testów Atomic Red Team (osobne wiersze dla każdego testu)</h3>')
    html.append('<table class="matrix-table"><tr><th>Technique ID</th><th>Nazwa</th><th>Taktyki</th><th>Status</th><th>Tytuł testu</th><th>Typ(y) skryptów</th></tr>')
    for row in test_status:
        html.append(f"<tr><td>{row['Technique ID']}</td><td>{row['Name']}</td><td>{row['Tactics']}</td><td><span class='badge badge-ART-exist'>ART-exist</span></td><td>{row['Test Title']}</td><td>{row['Scripts']}</td></tr>")
    html.append("</table>")

    html.append("</div>")

    raport_folder = os.path.join(REPORT_DIR, mapping)
    ensure_dir(raport_folder)
    raport_path = os.path.join(raport_folder, "index.html")

    with open(raport_path, "w", encoding="utf-8") as f:
        f.write("\n".join(html))

    print(f"\n[✓] Wygenerowano raport: {raport_path}\n")

def merge_pro():
    mapping, status_csv = wybierz_status_csv()
    alerts_dir = os.path.join("alerts", mapping)
    ensure_dir(ATOMIC_SCEN_DIR)
    if not os.path.isdir(alerts_dir):
        print(f"\n[!] Nie znaleziono folderu alertów: {alerts_dir}\n"
              f"Brak plików .md do aktualizacji dla mappingu '{mapping}'.\n"
              f"Pomijam ten mapping – wygeneruj najpierw alerty, jeśli chcesz korzystać z MERGE PRO.\n")
        return
    all_md = [f for f in os.listdir(alerts_dir) if f.endswith(".md")]
    patched = 0
    for alert_md in all_md:
        md_path = os.path.join(alerts_dir, alert_md)
        html_path = md_path.replace(".md", ".html")
        with open(md_path, encoding="utf-8") as f:
            content = f.read()
        tid_match = re.search(r'\*\*Technika:\*\*\s*([^\s\n]+)', content)
        if not tid_match:
            continue
        tid = tid_match.group(1).strip().upper()
        atomic_tests = get_atomic_tests_for_tid(tid)
        if not atomic_tests:
            continue

        gh_url = f"https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/{tid}"
        section_md = "\n\n---\n\n## Atomic Red Team – dostępne testy dla tej techniki\n"
        section_html = "<div style='background:#eaf4ff;border-radius:8px;padding:15px 16px;margin-top:25px;'><b>Atomic Red Team – dostępne testy dla tej techniki:</b><ul>"

        for t in atomic_tests:
            scen_path = os.path.join(ATOMIC_SCEN_DIR, tid, safe_filename(t['title']))
            ensure_dir(scen_path)
            section_md += f"\n### {t['title']}\n"
            section_md += f"**Opis:** {t['desc']}\n"
            section_html += f"<li><b>{t['title']}</b>"
            if t['desc']:
                section_md += f"\n{t['desc']}\n"
                section_html += f"<br><b>Opis:</b> {t['desc']}"
            for idx, (stype, code) in enumerate(t['scripts']):
                fname = f"test_{idx+1}.{ 'ps1' if stype == 'powershell' else 'cmd' if stype in ['cmd','bat'] else stype }"
                with open(os.path.join(scen_path, fname), "w", encoding="utf-8") as f:
                    f.write(code)
                section_md += f"\n<b>Polecenia testowe ({stype}):</b>\n```\n{code}\n```\n[Pobierz {fname}](../../{scen_path}/{fname})\n"
                section_html += f"<br><b>Polecenia testowe ({stype}):</b><pre style='white-space:pre-wrap;word-break:break-all;'>{code}</pre>"
                section_html += f"<a href='../../{scen_path}/{fname}'>Pobierz {fname}</a><br>"
            if t['cleanup']:
                for idx, (stype, code) in enumerate(t['cleanup']):
                    fname = f"cleanup_{idx+1}.{ 'ps1' if stype == 'powershell' else 'cmd' if stype in ['cmd','bat'] else stype }"
                    with open(os.path.join(scen_path, fname), "w", encoding="utf-8") as f:
                        f.write(code)
                    section_md += f"\n<b>Polecenia cleanup ({stype}):</b>\n```\n{code}\n```\n[Pobierz {fname}](../../{scen_path}/{fname})\n"
                    section_html += f"<b>Polecenia cleanup ({stype}):</b><pre style='white-space:pre-wrap;word-break:break-all;'>{code}</pre>"
                    section_html += f"<a href='../../{scen_path}/{fname}'>Pobierz {fname}</a><br>"
            with open(os.path.join(scen_path, "README.md"), "w", encoding="utf-8") as f:
                f.write(f"# {t['title']}\n\nOpis: {t['desc']}\n\n")
                for stype, code in t['scripts']:
                    f.write(f"## Polecenia testowe ({stype}):\n```\n{code}\n```\n")
                for stype, code in t['cleanup']:
                    f.write(f"## Polecenia cleanup ({stype}):\n```\n{code}\n```\n")
                f.write(f"\n---\nOryginalny test:\n\n```\n{t['raw']}\n```\n")
                f.write(f"\n[Zobacz oryginał na GitHubie]({gh_url})\n")
            section_html += "</li>"
        section_html += f"</ul><a href='{gh_url}' target='_blank'>Zobacz wszystkie testy na GitHubie</a></div>"
        section_md += f"\n[Zobacz testy na GitHubie]({gh_url})\n"

        content = re.sub(r'(?s)\n*-+\n+## Atomic Red Team.+?(?=\n#|\Z)', '', content)
        content += section_md
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(content)

        if os.path.exists(html_path):
            with open(html_path, encoding="utf-8") as f:
                html_content = f.read()
            html_content = re.sub(
                r'<div style=[\'"]background:#eaf4ff;.*?Atomic Red Team – dostępne testy.*?</div>',
                '', html_content, flags=re.DOTALL)

            # 1. Spróbuj wstawić PO <div class="scenario-block">
            scenario_block_end = re.search(r'(<div\s+class="scenario-block".*?</div>)', html_content, re.DOTALL)
            if scenario_block_end:
                html_content = html_content.replace(
                    scenario_block_end.group(1),
                    scenario_block_end.group(1) + section_html,
                    1
                )
            # 2. Jeśli nie ma bloku scenario, doklej po głównym <div class="card">
            elif '<div class="card"' in html_content and '</div>' in html_content:
                first_card_close = html_content.find('</div>')
                html_content = html_content[:first_card_close] + section_html + html_content[first_card_close:]
            else:
                # fallback: doklej na koniec
                html_content = html_content.strip() + section_html

            # Dodaj CSS do zawijania w razie potrzeby
            if '<style>' in html_content:
                html_content = html_content.replace(
                    '<style>',
                    '<style>\n.card { word-break: break-word; }\npre { white-space: pre-wrap; word-break: break-all; }\n'
                )
            else:
                html_content = (
                    "<style>.card { word-break: break-word; } pre { white-space: pre-wrap; word-break: break-all; }</style>\n"
                    + html_content
                )
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
        patched += 1
        print(f"[+] Wygenerowano folder, skrypty i doklejono testy ART do: {alert_md} (+html)")

    print(f"\n[✓] Zaktualizowano {patched} plików alertów o testy ART (md + html) oraz utworzono foldery/scenariusze!\n")

def main():
    print("\n=== Mode 6: Atomic Coverage (Atomic Red Team) ===\n")
    print("1) Generuj macierz pokrycia (Atomic Coverage Matrix)")
    print("2) Merge PRO – generuj foldery/skrypty i opisy (md + html)")
    wyb = input("Wybierz tryb (1/2): ").strip()
    if wyb == "1":
        atomic_coverage_matrix()
    elif wyb == "2":
        merge_pro()

if __name__ == "__main__":
    main()
