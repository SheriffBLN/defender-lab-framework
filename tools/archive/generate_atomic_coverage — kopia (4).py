import os
import csv
import re
from datetime import datetime

try:
    from tools.shared_utils import (
        TACTICS_ORDER, MITRE_TACTICS, format_datetime, ensure_dir, safe_filename
    )
except ImportError:
    TACTICS_ORDER = [
        'initial-access', 'execution', 'persistence', 'privilege-escalation',
        'defense-evasion', 'credential-access', 'discovery', 'lateral-movement',
        'collection', 'command-and-control', 'exfiltration', 'impact'
    ]
    MITRE_TACTICS = {k: (k.replace("-", " ").title(), "") for k in TACTICS_ORDER}
    def format_datetime():
        return datetime.now().strftime("%Y-%m-%d %H:%M")
    def ensure_dir(path):
        os.makedirs(path, exist_ok=True)
    def safe_filename(s):
        return re.sub(r'[^a-zA-Z0-9_\-]', '_', s)

MAPPING_DIR = "mapping"
ART_REPO_DIR = "atomic_red_team_repo/atomics"
REPORT_DIR = "report/atomic_coverage"
ATOMIC_SCEN_DIR = "scenarios/atomic_tests"
MITRE_CSV = "tools/enterprise_attack.csv"

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

def escape(s):
    return str(s).replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')

def art_badge(stype):
    if stype.lower() == "powershell":
        return '<span class="badge badge-ps">PowerShell</span>'
    elif stype.lower() in ["cmd", "bat"]:
        return '<span class="badge badge-cmd">CMD</span>'
    else:
        return f'<span class="badge badge-total">{escape(stype)}</span>'

def parse_md(content):
    tid_match = re.search(r'\*\*(?:Technique ID|Technika):\*\*\s*([^\s\n]+)', content)
    tname_match = re.search(r'\*\*(?:Name|Nazwa):\*\*\s*([^\n*]+)', content)
    tactics_match = re.search(r'\*\*(?:Tactics|Taktyki):\*\*\s*([^\n*]+)', content)
    mitre_desc_match = re.search(
        r'\*\*(?:Description|MITRE Description):\*\*\s*([\s\S]+?)(\*\*(?:MITRE Link|Link)|Autor:|\n#|$)', content)
    mitre_link_match = re.search(r'\*\*(?:MITRE Link|Link):\*\*\s*(https://attack\.mitre\.org/techniques/[^\s\)]+)', content)
    author_match = re.search(r'(?:\*\*Autor:\*\*|Autor:)\s*([^\n*]+)', content)
    tid = tid_match.group(1).strip().upper() if tid_match else "UNKNOWN"
    tname = tname_match.group(1).strip() if tname_match else "(brak nazwy techniki)"
    tactics = tactics_match.group(1).strip() if tactics_match else "(brak danych)"
    mitre_desc = mitre_desc_match.group(1).strip() if mitre_desc_match else "(brak opisu)"
    mitre_link = mitre_link_match.group(1).strip() if mitre_link_match else "(brak linku)"
    author = author_match.group(1).strip() if author_match else "Anon"
    return tid, tname, tactics, mitre_desc, mitre_link, author

def load_mitre_db():
    db = {}
    try:
        with open(MITRE_CSV, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                tid = row["ID"].strip().upper()
                db[tid] = {
                    "name": row.get("Name", "").strip(),
                    "tactics": row.get("Tactics", "").strip(),
                    "description": row.get("Description", "").strip(),
                    "mitre_link": row.get("MITRE Link", "").strip(),
                }
    except Exception as e:
        print("Nie udało się załadować bazy technik MITRE:", e)
        db = {}
    return db

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
def generate_art_html(tid, technique_name, tactic_str, atomic_tests, mitre_desc, mitre_link, author=""):
    ps, cmd, total = 0, 0, len(atomic_tests)
    for t in atomic_tests:
        for stype, _ in t["scripts"]:
            if stype.lower() == "powershell":
                ps += 1
            elif stype.lower() in ["cmd", "bat"]:
                cmd += 1
    now = format_datetime()
    html = f"""<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="UTF-8">
  <title>Alert: {escape(technique_name)} – Atomic Red Team</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 2rem; background: #f6f7fb; }}
    .card {{ background: #fff; border-radius: 10px; box-shadow: 0 2px 6px #bbb; padding: 2rem; max-width: 800px; margin: auto; }}
    h1 {{ margin-top: 0; font-size: 2rem; }}
    .desc, .id, .link, .author, .tactic, .status {{ margin-bottom: 1.1em; }}
    .meta {{ font-size: .95em; color: #555; margin-bottom: .8em; }}
    .section {{ font-size: .99em; }}
    .scenario-block {{ background: #f4f0d9; border-radius: 7px; padding: 1em 1.2em; margin-bottom: 1.2em; color:#4a4500; font-size:1.07em; border-left:5px solid #e1c553; }}
    pre {{ background: #eee; padding: .7em 1em; border-radius: 5px; white-space: pre-wrap; word-break: break-all; overflow-x: auto; max-width: 100%; }}
    code {{ background: #f6f6f6; padding: 2px 5px; border-radius: 2px; }}
    ul {{ margin-left: 1.6em; }}
    textarea {{ width:100%; border-radius:8px; border:1.5px solid #d6d6d6; font-size:1.08em; margin-top:8px; padding:8px; background:#faf8ed;}}
    .badge-ok {{ background: #43a047; color: #fff; }}
    .art-accordion {{ margin-bottom:10px; }}
    .art-accordion-btn {{ background:#eaf4ff; color:#1d3557; cursor:pointer; padding:9px 18px; width:100%; text-align:left; border:none; border-radius:7px; font-size:1.1em; font-weight:600; margin-bottom:2px; transition:background 0.18s;}}
    .art-accordion-btn:hover {{ background:#ddefff; }}
    .art-accordion-content {{ display:none; background:#f7fafd; border:1px solid #e3e3e3; border-radius:0 0 7px 7px; padding:13px 18px; margin-bottom:2px; }}
    .test-cleanup {{ background:#fffde7; border-left:4px solid #ffd700; margin-top:11px; padding:7px 12px; border-radius:5px; }}
    .badge {{ display:inline-block; border-radius:8px; padding:2px 10px; font-size:.94em; color:#fff; margin-right:7px; }}
    .badge-ps {{ background:#1976d2; }}
    .badge-cmd {{ background:#29b300; }}
    .badge-total {{ background:#888; }}
    .art-checklist {{ background: #f7fff7; border-radius:6px; margin-top:10px; padding:7px 15px; }}
    .art-checklist label {{ font-size:1.02em; margin-right:20px; }}
    .art-checklist input[type=checkbox] {{ transform: scale(1.2); margin-right:8px; }}
    .art-copy-btn {{ background:#fff; border:1px solid #bdbdbd; color:#1976d2; border-radius:6px; padding:3px 11px; margin-left:8px; font-size:0.97em; cursor:pointer;}}
    .art-copy-btn:active {{ background:#eaf4ff;}}
    .eksport-btn {{ background:#c5e1a5; color:#1b4b2b; border-radius:7px; border:none; padding:9px 17px; margin:11px 0 5px 0; font-weight:600; cursor:pointer; }}
    .eksport-btn:hover {{ background:#b2dfdb; }}
  </style>
  <script>
    function toggleArtAccordion(btn) {{
      var content = btn.nextElementSibling;
      content.style.display = (content.style.display === "block") ? "none" : "block";
    }}
    function copyArtCode(btn) {{
      var code = btn.previousElementSibling.textContent;
      navigator.clipboard.writeText(code);
      btn.textContent = "Skopiowano!";
      setTimeout(()=>btn.textContent="Kopiuj", 1100);
    }}
    function saveChecklist(tid, id, scenarioBlockId, testLabel) {{
      var uniqueId = tid + '-' + id;
      var div = document.getElementById('checklist-' + uniqueId);
      var chks = div.querySelectorAll('input[type=checkbox]');
      var states = Array.from(chks).map(x => x.checked);
      localStorage.setItem('art-checklist-' + uniqueId, JSON.stringify(states));
      var allChecked = states.every(x=>x);
      document.getElementById('tested-badge-' + uniqueId).style.display = allChecked ? 'inline-block' : 'none';
      if(allChecked && scenarioBlockId && testLabel) {{
        var now = new Date().toLocaleString("pl-PL");
        var msg = `✅ [${{now}}] Przetestowano: ${{testLabel}} – utworzono alert w Defenderze`;
        var scenario = document.getElementById(scenarioBlockId);
        if(scenario && !scenario.value.includes(msg)) {{
          scenario.value += "\\n" + msg;
        }}
      }}
    }}
    function loadChecklist(tid, id, scenarioBlockId, testLabel) {{
      var uniqueId = tid + '-' + id;
      var div = document.getElementById('checklist-' + uniqueId);
      if (!div) return;
      var chks = div.querySelectorAll('input[type=checkbox]');
      var states = JSON.parse(localStorage.getItem('art-checklist-' + uniqueId) || '[]');
      chks.forEach((chk, i) => {{ chk.checked = !!states[i]; }});
      var allChecked = states.length && states.every(x=>x);
      document.getElementById('tested-badge-' + uniqueId).style.display = allChecked ? 'inline-block' : 'none';
      if(allChecked && scenarioBlockId && testLabel) {{
        var now = new Date().toLocaleString("pl-PL");
        var msg = `✅ [${{now}}] Przetestowano: ${{testLabel}} – utworzono alert w Defenderze`;
        var scenario = document.getElementById(scenarioBlockId);
        if(scenario && !scenario.value.includes(msg)) {{
          scenario.value += "\\n" + msg;
        }}
      }}
    }}
    function resetChecklist(tid, id, scenarioBlockId, testLabel) {{
      var uniqueId = tid + '-' + id;
      localStorage.removeItem('art-checklist-' + uniqueId);
      loadChecklist(tid, id, scenarioBlockId, testLabel);
    }}
    function eksportujProgres(tid, total_tests) {{
      let out = [];
      for(let i=1; i<=total_tests; i++) {{
        let id = 'art' + String(i).padStart(2,'0');
        let uniqueId = tid + '-' + id;
        let div = document.getElementById('checklist-' + uniqueId);
        if(!div) continue;
        let label = div.getAttribute('data-label') || ("Atomic Test " + i);
        let chks = div.querySelectorAll('input[type=checkbox]');
        let states = Array.from(chks).map(x => x.checked);
        if(states.every(x=>x)) {{
          let now = new Date().toLocaleString("pl-PL");
          out.push(`✅ [${{now}}] Przetestowano: ${{label}} – utworzono alert w Defenderze`);
        }}
      }}
      let box = document.getElementById('eksportChecklist');
      box.style.display = 'block';
      box.value = out.join("\\n");
      box.select();
      document.execCommand('copy');
    }}
    window.addEventListener('DOMContentLoaded', function() {{
      var tid = document.body.getAttribute('data-tid');
      var total_tests = Number(document.body.getAttribute('data-total-tests')||'1');
      for(let i=1; i<=total_tests; i++) {{
        let id = 'art' + String(i).padStart(2,'0');
        let div = document.getElementById('checklist-' + tid + '-' + id);
        if(!div) continue;
        let scenarioBlockId = div.getAttribute('data-scenario');
        let testLabel = div.getAttribute('data-label');
        loadChecklist(tid, id, scenarioBlockId, testLabel);
        div.querySelectorAll('input[type=checkbox]').forEach(function(chk) {{
          chk.onchange = function() {{ saveChecklist(tid, id, scenarioBlockId, testLabel); }};
        }});
      }}
    }});
  </script>
</head>
<body data-tid="{escape(tid)}" data-total-tests="{total}">
<div class="card">
  <h1>Alert: {escape(technique_name)}</h1>
  <div class="meta"><b>Technique ID:</b> {escape(tid)}</div>
  <div class="tactic section"><b>Tactics:</b> {escape(tactic_str)}</div>
  <div class="status section"><b>Status:</b> ART / do walidacji</div>
  <div class="desc section"><b>MITRE Description:</b><br>{escape(mitre_desc) or '<i>(brak)</i>'}</div>
  <div class="link section"><b>MITRE Link:</b> <a href="{escape(mitre_link)}" target="_blank">{escape(mitre_link)}</a></div>
  <div class="scenario-block">
    <b>Twój opis scenariusza:</b><br>
    <textarea id="scenarioBlock" rows="7" readonly>
Tutaj wpisz opis scenariusza lub eksportuj progres z checklisty poniżej.
    </textarea>
  </div>
  <button onclick="eksportujProgres('{escape(tid)}',{total})" class="eksport-btn">Eksportuj progres (do MD)</button>
  <textarea id="eksportChecklist" rows="4" style="width:100%;margin-top:10px;display:none;"></textarea>
  <div style='background:#eaf4ff;border-radius:8px;padding:15px 16px;margin-top:25px;'>
    <b>Atomic Red Team – dostępne testy dla tej techniki:</b>
    <div style="margin-bottom:10px;">
      <span class="badge badge-total">{total} testów</span>
      <span class="badge badge-ps">{ps} PowerShell</span>
      <span class="badge badge-cmd">{cmd} CMD</span>
      <a href='https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/{escape(tid)}' target='_blank' style="float:right;">Zobacz na GitHubie</a>
    </div>
"""
    for idx, t in enumerate(atomic_tests, 1):
        uid = f"art{idx:02d}"
        unique_id = f"{tid}-{uid}"
        test_label = f"Atomic Test {idx}: {escape(t['title'])}"
        html += f"""
    <div class="art-accordion">
      <button class="art-accordion-btn" onclick="toggleArtAccordion(this)">
        {art_badge(t["scripts"][0][0]) if t["scripts"] else ''}
        <b>{test_label}</b>
        <span id="tested-badge-{unique_id}" class="badge badge-ok" style="display:none; float:right;">PRZETESTOWANE</span>
      </button>
      <div class="art-accordion-content">
        <div class="test-desc"><b>Opis:</b> {escape(t['desc'])}</div>
"""
        for sidx, (stype, code) in enumerate(t["scripts"], 1):
            html += f"""
        <div>
          <b>Polecenia testowe ({escape(stype)}):</b>
          <pre>{escape(code)}</pre>
          <button class="art-copy-btn" onclick="copyArtCode(this)">Kopiuj</button>
        </div>
"""
            scen_path = os.path.join(ATOMIC_SCEN_DIR, tid, safe_filename(t['title']))
            fname = f"test_{sidx}.{ 'ps1' if stype == 'powershell' else 'cmd' if stype in ['cmd','bat'] else stype }"
            relpath = os.path.relpath(os.path.join(scen_path, fname), REPORT_DIR)
            html += f"""<a href="{relpath}" download>Pobierz {fname}</a><br>"""
        if t["cleanup"]:
            for cidx, (stype, code) in enumerate(t["cleanup"], 1):
                html += f"""
        <div class="test-cleanup">
          <b>Cleanup ({escape(stype)}):</b>
          <pre>{escape(code)}</pre>
        </div>
"""
                scen_path = os.path.join(ATOMIC_SCEN_DIR, tid, safe_filename(t['title']))
                fname = f"cleanup_{cidx}.{ 'ps1' if stype == 'powershell' else 'cmd' if stype in ['cmd','bat'] else stype }"
                relpath = os.path.relpath(os.path.join(scen_path, fname), REPORT_DIR)
                html += f"""<a href="{relpath}" download>Pobierz {fname}</a><br>"""
        html += f"""
        <div class="art-checklist" id="checklist-{unique_id}" data-scenario="scenarioBlock" data-label="{test_label}">
          <label><input type="checkbox"> Uruchomiono test</label><br>
          <label><input type="checkbox"> Wykonano cleanup</label><br>
          <label><input type="checkbox"> Zdarzenie widoczne w Defenderze</label><br>
          <label><input type="checkbox"> Utworzono alert</label><br>
          <button onclick="resetChecklist('{tid}','{uid}','scenarioBlock','{test_label}')">Resetuj</button>
        </div>
      </div>
    </div>
"""
    html += f"""
  </div>
  <div class="author section"><b>Author:</b> {escape(author)}</div>
</div>
</body>
</html>
"""
    return html

def merge_pro():
    mitre_db = load_mitre_db()
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
        tid, tname, tactics, mitre_desc, mitre_link, author = parse_md(content)
        # Pobierz pełne dane z MITRE jeśli coś jest puste lub domyślne
        if tid in mitre_db:
            if not tname or tname == "(brak nazwy techniki)":
                tname = mitre_db[tid]["name"]
            if not tactics or tactics == "(brak danych)":
                tactics = mitre_db[tid]["tactics"]
            if not mitre_desc or mitre_desc == "(brak opisu)":
                mitre_desc = mitre_db[tid]["description"]
            if not mitre_link or mitre_link == "(brak linku)":
                mitre_link = mitre_db[tid]["mitre_link"]
        atomic_tests = get_atomic_tests_for_tid(tid)
        if tid == "UNKNOWN":
            print(f"UWAGA: Plik {alert_md} ma niepełne dane! Pomijam.")
            continue
        if not atomic_tests:
            print(f" - Brak testów ART dla techniki {tid}. Pomijam {alert_md}.")
            continue
        for t in atomic_tests:
            scen_path = os.path.join(ATOMIC_SCEN_DIR, tid, safe_filename(t['title']))
            ensure_dir(scen_path)
            for idx, (stype, code) in enumerate(t["scripts"], 1):
                fname = f"test_{idx}.{ 'ps1' if stype == 'powershell' else 'cmd' if stype in ['cmd','bat'] else stype }"
                with open(os.path.join(scen_path, fname), "w", encoding="utf-8") as f:
                    f.write(code)
            for idx, (stype, code) in enumerate(t["cleanup"], 1):
                fname = f"cleanup_{idx}.{ 'ps1' if stype == 'powershell' else 'cmd' if stype in ['cmd','bat'] else stype }"
                with open(os.path.join(scen_path, fname), "w", encoding="utf-8") as f:
                    f.write(code)
            with open(os.path.join(scen_path, "README.md"), "w", encoding="utf-8") as f:
                f.write(f"# {t['title']}\n\nOpis: {t['desc']}\n\n")
                for stype, code in t["scripts"]:
                    f.write(f"## Polecenia testowe ({stype}):\n```\n{code}\n```\n")
                for stype, code in t["cleanup"]:
                    f.write(f"## Polecenia cleanup ({stype}):\n```\n{code}\n```\n")
                f.write(f"\n---\nOryginalny test:\n\n```\n{t['raw']}\n```\n")
        html_code = generate_art_html(
            tid, tname, tactics, atomic_tests, mitre_desc, mitre_link, author=author
        )
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_code)
        patched += 1
        print(f"[+] Zaktualizowano: {alert_md} (+html)")

    print(f"\n[✓] Zaktualizowano {patched} plików alertów o nowe raporty ART (md + html) oraz utworzono foldery/scenariusze!\n")

def main():
    print("\n=== Mode 6: Atomic Coverage (Atomic Red Team) ===\n")
    print("1) Generuj macierz pokrycia (Atomic Coverage Matrix)")
    print("2) Merge PRO – generuj foldery/skrypty i czytelny raport HTML (PL) + eksport progresu do MD")
    wyb = input("Wybierz tryb (1/2): ").strip()
    if wyb == "1":
        atomic_coverage_matrix()
    elif wyb == "2":
        merge_pro()

if __name__ == "__main__":
    main()
