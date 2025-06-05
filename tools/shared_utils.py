import os
import csv
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from collections import defaultdict

STATUS_CSV_FIELDS = [
    "Technique ID","Name","Tactics","Status","Linked Rule",
    "Liczba wykryć","Author","Description","MITRE Link"
]

STATUSES = [
    {"value": "Tested", "label": "Przetestowane", "bg": "#a3e4a1", "badge": "#43a047", "desc": "Reguła i detekcja przeszły testy"},
    {"value": "Audit", "label": "Audit (tryb testowy)", "bg": "#ffe9a3", "badge": "#ffb300", "desc": "W trybie audytu – wymaga walidacji"},
    {"value": "Pending", "label": "Do przetestowania", "bg": "#ffb4b4", "badge": "#e53935", "desc": "Do zbudowania/testu"},
    {"value": "Disabled", "label": "Wyłączone", "bg": "#c3c3c3", "badge": "#757575", "desc": "Reguła wyłączona"},
    {"value": "Suppressed", "label": "Stłumione", "bg": "#ececec", "badge": "#bdbdbd", "desc": "Alerty stłumione"}
]
STATUS_BG_COLORS = {s["value"]: s["bg"] for s in STATUSES}
BADGE_COLORS = {s["value"]: s["badge"] for s in STATUSES}

TACTICS_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"
]

MITRE_TACTICS = {
    'Reconnaissance': 'TA0043',
    'Resource Development': 'TA0042',
    'Initial Access': 'TA0001',
    'Execution': 'TA0002',
    'Persistence': 'TA0003',
    'Privilege Escalation': 'TA0004',
    'Defense Evasion': 'TA0005',
    'Credential Access': 'TA0006',
    'Discovery': 'TA0007',
    'Lateral Movement': 'TA0008',
    'Collection': 'TA0009',
    'Command and Control': 'TA0011',
    'Exfiltration': 'TA0010',
    'Impact': 'TA0040',
}

def heatmap_color(count):
    # Koloruj już od 1+ na żółto, potem pomarańcz/czerwień/fiolet.
    if count >= 100:
        return "#6f42c1"  # fiolet
    elif count >= 50:
        return "#d7263d"  # mocna czerwień
    elif count >= 20:
        return "#ff704d"  # pomarańcz
    elif count >= 10:
        return "#ffd700"  # intensywna żółć
    elif count >= 1:
        return "#fff7ae"  # jasno-żółty (dla każdego alertu 1+)
    else:
        return "#ececec"  # brak

def safe_filename(value):
    return re.sub(r'[\\/:"*?<>| ]', '_', str(value))[:40]

def format_datetime(dt=None):
    return (dt or datetime.now()).strftime('%Y-%m-%d %H:%M:%S')

def ensure_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)

def check_files_exist(paths):
    missing = []
    for path in paths:
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

def print_env_diagnostics(paths=None, exit_on_fail=True):
    print("\n[DIAGNOSTYKA] Sprawdzam środowisko:")
    print(f"Python: {sys.version}")
    print(f"CWD: {os.getcwd()}")
    missing = []
    if paths:
        missing = check_files_exist(paths)
        if missing:
            print("\n[!] Brak wymaganych plików: ", ", ".join(missing))
            if exit_on_fail:
                print("\nPrzerwano. Uzupełnij brakujące pliki i spróbuj ponownie.")
                sys.exit(1)
    return missing

def load_techniques_db(csv_path="tools/enterprise_attack.csv"):
    db = {}
    with open(csv_path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            tid = row["ID"].strip().upper()
            db[tid] = {
                "name": row["Name"].strip(),
                "tactics": [t.strip() for t in row["Tactics"].split(",") if t.strip()],
                "description": row.get("Description", ""),
                "mitre_link": row.get("MITRE Link", "")
            }
    return db

def load_alert_counts(csv_path="tools/helpers/last30days_alerts.csv"):
    counts = {}
    if not os.path.exists(csv_path):
        print(f"[DEBUG] Nie znaleziono pliku {csv_path}")
        return counts
    with open(csv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tid = (
                row.get("AttackTechniques")
                or row.get("Technique ID")
                or row.get("technique_id")
                or ""
            ).strip().upper()
            try:
                cnt = int(row.get("Count", 1))
            except Exception:
                cnt = 1
            if tid:
                counts[tid] = cnt
    print("[DEBUG] Załadowane counts z last30days_alerts.csv:", counts)
    return counts

def badge_html(status):
    color = BADGE_COLORS.get(status, "#aaa")
    return f'<span class="badge badge-{status}" style="background:{color};">{status}</span>'
def generate_matrix_html(
    status_rows, title, apt_folder, 
    tactics_order=TACTICS_ORDER, 
    show_counts=False, show_linked_rule=False, 
    show_heatmap=True, alert_counts=None
):
    from collections import defaultdict
    import json
    matrix = defaultdict(list)
    for r in status_rows:
        tactics = [t.strip().lower().replace(" ", "-") for t in r["Tactics"].split(",") if t.strip()]
        for t in tactics:
            if t in tactics_order:
                matrix[t].append(r)
    now = format_datetime()
    html = [
        "<style>",
        "body { font-family: Segoe UI, Arial, sans-serif; }",
        ".container { max-width:1200px; margin:0 auto; }",
        ".matrix-table { border-collapse:collapse; width:100%; margin-bottom:28px; }",
        ".matrix-table th { background:#dbeafe; color:#1e293b; padding:7px 0; font-size:1.07em; border:1px solid #e3e3e3; }",
        ".matrix-table td { vertical-align:top; border:1px solid #e3e3e3; min-width:94px; padding:2px; }",
        ".matrix-technique { border-radius:7px; box-shadow:1px 2px 8px #e6e6e6; margin:7px 0; padding:7px 7px 5px 7px; font-size:.97em; font-weight:500; background:#fff; }",
        ".badge { padding:2px 12px 2px 12px; border-radius:8px; color:#fff; font-size:.92em; font-weight:700; letter-spacing:.05em; display:inline-block; }",
        "a.link-alert { color:#1e50a2; text-decoration:underline; }",
        ".changelog-toggle { cursor:pointer; color:#1d51a8; text-decoration:underline; font-size:1.04em; }",
        ".changelog-content { display:none; background:#f8f9fd; border-radius:7px; margin-top:1em; padding:1em 1.6em; }",
        ".changelog-entry { margin-bottom: .8em; }",
        ".techid-label { color:#888; font-size:.98em; margin-right:10px; }",
        "</style>",
        "<script>",
        "function toggleChangelog() {",
        "var x = document.getElementById('changelog-content');",
        "if(x.style.display==='block') x.style.display='none';",
        "else x.style.display='block';",
        "}",
        "</script>",
        "<div class=\"container\">",
        f'<h1>{title or "🛡️ Macierz MITRE ATT&CK"}</h1>',
        f'<div style="margin:10px 0 18px 0; font-size:1.18em;">Matryca wygenerowana dla: <b>{apt_folder or ""}</b></div>',
        f'<p style="color:#557;">Wygenerowano: {now}</p>',
        '<h2>Status macierzy (Tested / Audit / Pending)</h2>',
        '<table class="matrix-table"><tr>'
    ]
    for tactic in TACTICS_ORDER:
        html.append(f"<th>{tactic}</th>")
    html.append("</tr><tr>")
    for tactic in TACTICS_ORDER:
        html.append("<td>")
        if matrix.get(tactic):
            for row in matrix[tactic]:
                status = row.get("Status","Pending")
                bg = STATUS_BG_COLORS.get(status, "#fff")
                tid = row["Technique ID"].strip().upper()
                name = row["Name"]
                html.append(
                    f'<div class="matrix-technique" style="background:{bg};">'
                    f'<b>{tid}</b><br>{name}'
                    f'<br>{badge_html(status)}'
                    '</div>'
                )
        else:
            html.append('<div class="matrix-technique" style="background:#ececec;">–</div>')
        html.append("</td>")
    html.append("</tr></table>")

    # === HEATMAPA (z agendą kolorów)
    if show_heatmap and status_rows:
        html.append('<h2>🔥 Heatmapa wyzwolonych technik</h2>')
        html.append('<table class="matrix-table"><tr>')
        for tactic in TACTICS_ORDER:
            html.append(f"<th>{tactic}</th>")
        html.append("</tr><tr>")
        for tactic in TACTICS_ORDER:
            html.append("<td>")
            if matrix.get(tactic):
                for row in matrix[tactic]:
                    tid = row["Technique ID"].strip().upper()
                    count = (alert_counts or {}).get(tid, 0)
                    color = heatmap_color(count)
                    html.append(
                        f'<div class="matrix-technique" style="background:{color};border:1.5px solid #b6b6b6;">'
                        f'<b>{tid}</b><br>{row["Name"]}'
                        f'<div style="margin-top:5px;">'
                        f'<span style="font-size:1.09em;font-weight:600;color:#d7263d;">{"🔥" if count else "–"}</span> '
                        f'<span style="font-size:1.04em;">{count} alertów</span>'
                        '</div></div>'
                    )
            else:
                html.append('<div class="matrix-technique" style="background:#ececec;">–</div>')
            html.append("</td>")
        html.append("</tr></table>")
        html.append("""
        <div style="margin-top:12px; font-size:1.01em; color:#555;">
            <b>Legenda kolorów:</b>
            <span style="background:#fff7ae; padding:2px 8px; margin-right:8px;">1–9</span>
            <span style="background:#ffd700; padding:2px 8px; margin-right:8px;">10–19</span>
            <span style="background:#ff704d; padding:2px 8px; margin-right:8px;">20–49</span>
            <span style="background:#d7263d; padding:2px 8px; margin-right:8px; color:#fff;">50–99</span>
            <span style="background:#6f42c1; padding:2px 8px; margin-right:8px; color:#fff;">100+</span>
            <span style="background:#ececec; padding:2px 8px; margin-left:18px;">Brak</span>
        </div>
        """)

    # === TABELA STATUSÓW Z LINKAMI ===
    html.append('<h2>📊 Tabela statusów</h2>')
    html.append('<table class="matrix-table"><tr>'
                '<th>Tactics</th><th>Technique ID</th><th>Name</th>'
                '<th>Status</th><th>Alert HTML</th><th>Alert MD</th><th>Liczba alertów</th></tr>')
    for row in status_rows:
        status = row.get("Status","Pending")
        tactics = row.get("Tactics","")
        tid = row["Technique ID"].strip().upper()
        name = row["Name"]
        base_alert = os.path.splitext(os.path.basename(row.get("Linked Rule","") or ""))[0]
        alerts_dir = os.path.join("alerts", apt_folder)
        html_path = os.path.join(alerts_dir, f"{base_alert}.html")
        md_path   = os.path.join(alerts_dir, f"{base_alert}.md")
        html_link = html_path if os.path.exists(html_path) else ""
        md_link = md_path if os.path.exists(md_path) else ""
        html_col = f'<a class="link-alert" href="../{os.path.relpath(html_link, start="report")}" target="_blank">{html_link}</a>' if html_link else "-"
        md_col = f'<a class="link-alert" href="../{os.path.relpath(md_link, start="report")}" target="_blank">{md_link}</a>' if md_link else "-"
        liczba_alertow = (alert_counts or {}).get(tid, "") if alert_counts else row.get("Liczba wykryć","")
        html.append(
            f"<tr style='background:{STATUS_BG_COLORS.get(status, '#fff')}'>"
            f"<td>{tactics}</td>"
            f"<td>{tid}</td>"
            f"<td>{name}</td>"
            f"<td>{badge_html(status)}</td>"
            f"<td>{html_col}</td>"
            f"<td>{md_col}</td>"
            f"<td>{liczba_alertow}</td>"
            "</tr>"
        )
    html.append("</table>")

    # === ROZWIJANA HISTORIA ZMIAN ===
    html.append("""
    <h2 style="margin-top:3.2em">📝 <span class="changelog-toggle" onclick="toggleChangelog()">Pokaż/ukryj historię zmian (wszystkie techniki)</span></h2>
    <div id="changelog-content" class="changelog-content">
    """)
    for row in status_rows:
        techid = row.get("Technique ID", "–")
        name = row.get("Name", "")
        historia_json = row.get("ChangeHistory", "") or row.get("Historia zmian", "")
        try:
            entries = json.loads(historia_json) if historia_json else []
        except Exception:
            entries = []
        if not entries:
            continue
        html.append(f'<div class="changelog-entry"><span class="techid-label"><b>{techid}</b> {name}</span><ul style="margin:0 0 0 1.6em">')
        for e in entries:
            html.append(f'<li>{e["time"]} &mdash; <b>{e["user"]}</b></li>')
        html.append('</ul></div>')
    html.append("</div>")
    html.append("</div>")
    return "\n".join(html)
def generate_alert_html(
    technique_id, technique_name, tactics, status, author, scenario_desc, mitre_desc, mitre_link, mitre_tactics=None
):
    def tactic_to_link(tactic):
        tac_key = tactic.lower().replace(" ", "-")
        label, ta_id = MITRE_TACTICS.get(tac_key, (tactic.title(), ""))
        if ta_id:
            url = f'https://attack.mitre.org/tactics/{ta_id}/'
            return f'<a href="{url}" target="_blank">{label} ({ta_id})</a>'
        return label
    tactics_clean = []
    if isinstance(mitre_tactics, (list, tuple)):
        tactics_clean = mitre_tactics
    elif isinstance(mitre_tactics, str):
        tactics_clean = [x.strip() for x in mitre_tactics.split(",") if x.strip()]
    elif isinstance(tactics, str):
        tactics_clean = [x.strip() for x in tactics.split(",") if x.strip()]
    else:
        tactics_clean = tactics or []
    tactics_links = " / ".join([tactic_to_link(t) for t in tactics_clean]) if tactics_clean else "-"
    return f"""<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="UTF-8">
  <title>Alert: {technique_name}</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 2rem; background: #f6f7fb; }}
    .card {{ background: #fff; border-radius: 10px; box-shadow: 0 2px 6px #bbb; padding: 2rem; max-width: 700px; margin: auto; }}
    h1 {{ margin-top: 0; font-size: 2rem; }}
    .desc, .id, .link, .author, .tactic, .status {{ margin-bottom: 1.1em; }}
    .meta {{ font-size: .95em; color: #555; margin-bottom: .8em; }}
    .section {{ font-size: .99em; }}
    .scenario-block {{ background: #f4f0d9; border-radius: 7px; padding: 1em 1.2em; margin-bottom: 1.2em; color:#4a4500; font-size:1.07em; border-left:5px solid #e1c553; }}
    pre {{ background: #eee; padding: .7em 1em; border-radius: 5px; }}
    code {{ background: #f6f6f6; padding: 2px 5px; border-radius: 2px; }}
    ul {{ margin-left: 1.6em; }}
  </style>
</head>
<body>
<div class="card">
  <h1>Alert: {technique_name}</h1>
  <div class="meta"><b>Technique ID:</b> {technique_id}</div>
  <div class="tactic section"><b>Tactics:</b> {tactics_links}</div>
  <div class="status section"><b>Status:</b> {status}</div>
  <div class="scenario-block"><b>Twój opis scenariusza:</b><br>{scenario_desc or "<i>(brak opisu scenariusza)</i>"}</div>
  <div class="desc section"><b>MITRE Description:</b><br>{mitre_desc or "<i>(brak)</i>"}</div>
  <div class="link section"><b>MITRE Link:</b> <a href="{mitre_link}" target="_blank">{mitre_link or ""}</a></div>
  <div class="author section"><b>Author:</b> {author}</div>
</div>
</body>
</html>
"""
def md_to_html_basic(md_text):
    html_lines = []
    for line in md_text.splitlines():
        line = line.replace("<", "&lt;").replace(">", "&gt;")
        line = re.sub(r'^###### (.*)', r'<h6>\1</h6>', line)
        line = re.sub(r'^##### (.*)', r'<h5>\1</h5>', line)
        line = re.sub(r'^#### (.*)', r'<h4>\1</h4>', line)
        line = re.sub(r'^### (.*)', r'<h3>\1</h3>', line)
        line = re.sub(r'^## (.*)', r'<h2>\1</h2>', line)
        line = re.sub(r'^# (.*)', r'<h1>\1</h1>', line)
        line = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', line)
        line = re.sub(r'\[(.*?)\]\((.*?)\)', r'<a href="\2" target="_blank">\1</a>', line)
        line = re.sub(r'^\s*-\s(.*)', r'<li>\1</li>', line)
        html_lines.append(line)
    html_block = "\n".join(html_lines)
    if '<li>' in html_block:
        html_block = re.sub(r'((?:<li>.*?</li>\n?)+)', r'<ul>\1</ul>\n', html_block, flags=re.DOTALL)
    html_block = re.sub(r'^(?!<h\d>|<ul>|<li>|<b>|<a)(.+)$', r'<p>\1</p>', html_block, flags=re.MULTILINE)
    return html_block

def highlight_alertid(val):
    if not val or not str(val).strip():
        return ""
    url = f"https://security.microsoft.com/alerts/{val.strip()}"
    return f"<a href='{url}' style='color:#1976d2; font-weight:bold;' target='_blank' title='Otwórz alert w Microsoft 365 Defender'>{val}</a>"

def parse_additional_fields(field):
    try:
        data = json.loads(field) if field else {}
        out = {}
        if "CommandLine" in data: out["CommandLine"] = data["CommandLine"]
        if "ParentProcess" in data and isinstance(data["ParentProcess"], dict):
            if "CommandLine" in data["ParentProcess"]:
                out["ParentProc.Cmd"] = data["ParentProcess"]["CommandLine"]
        if "CreationTimeUtc" in data: out["CreationTimeUtc"] = data["CreationTimeUtc"]
        if "ImageFile" in data and isinstance(data["ImageFile"], dict):
            if "Name" in data["ImageFile"]: out["ImageFile"] = data["ImageFile"]["Name"]
        return out
    except Exception:
        return {}


