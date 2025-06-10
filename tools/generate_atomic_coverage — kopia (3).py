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

def escape(s):
    return str(s).replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')

def art_badge(stype):
    if stype.lower() == "powershell":
        return '<span class="badge badge-ps">PowerShell</span>'
    elif stype.lower() in ["cmd", "bat"]:
        return '<span class="badge badge-cmd">CMD</span>'
    else:
        return f'<span class="badge badge-total">{escape(stype)}</span>'

def generate_art_html(tid, technique_name, tactic_str, atomic_tests, mitre_desc, mitre_link, author=""):
    # Liczenie typów testów
    ps, cmd, total = 0, 0, len(atomic_tests)
    for t in atomic_tests:
        for stype, _ in t["scripts"]:
            if stype.lower() == "powershell":
                ps += 1
            elif stype.lower() in ["cmd", "bat"]:
                cmd += 1
    now = format_datetime()
    # Szablon HTML
    html = f"""<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="UTF-8">
  <title>Alert: {technique_name} – Atomic Red Team</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 2rem; background: #f6f7fb; }}
    .card {{ background: #fff; border-radius: 10px; box-shadow: 0 2px 6px #bbb; padding: 2rem; max-width: 760px; margin: auto; }}
    h1 {{ margin-top: 0; font-size: 2rem; }}
    .desc, .id, .link, .author, .tactic, .status {{ margin-bottom: 1.1em; }}
    .meta {{ font-size: .95em; color: #555; margin-bottom: .8em; }}
    .section {{ font-size: .99em; }}
    .scenario-block {{ background: #f4f0d9; border-radius: 7px; padding: 1em 1.2em; margin-bottom: 1.2em; color:#4a4500; font-size:1.07em; border-left:5px solid #e1c553; }}
    pre {{ background: #eee; padding: .7em 1em; border-radius: 5px; }}
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
    function saveChecklist(id, scenarioBlockId, testLabel) {{
      var div = document.getElementById('checklist-' + id);
      var chks = div.querySelectorAll('input[type=checkbox]');
      var states = Array.from(chks).map(x => x.checked);
      localStorage.setItem('art-checklist-' + id, JSON.stringify(states));
      var allChecked = states.every(x=>x);
      document.getElementById('tested-badge-' + id).style.display = allChecked ? 'inline-block' : 'none';
      if(allChecked && scenarioBlockId && testLabel) {{
        var now = new Date().toLocaleString("pl-PL");
        var msg = `✅ [${{now}}] Przetestowano: ${{testLabel}} – utworzono alert w Defenderze`;
        var scenario = document.getElementById(scenarioBlockId);
        if(scenario && !scenario.value.includes(msg)) {{
          scenario.value += "\\n" + msg;
        }}
      }}
    }}
    function loadChecklist(id, scenarioBlockId, testLabel) {{
      var div = document.getElementById('checklist-' + id);
      if (!div) return;
      var chks = div.querySelectorAll('input[type=checkbox]');
      var states = JSON.parse(localStorage.getItem('art-checklist-' + id) || '[]');
      chks.forEach((chk, i) => {{ chk.checked = !!states[i]; }});
      var allChecked = states.length && states.every(x=>x);
      document.getElementById('tested-badge-' + id).style.display = allChecked ? 'inline-block' : 'none';
      if(allChecked && scenarioBlockId && testLabel) {{
        var now = new Date().toLocaleString("pl-PL");
        var msg = `✅ [${{now}}] Przetestowano: ${{testLabel}} – utworzono alert w Defenderze`;
        var scenario = document.getElementById(scenarioBlockId);
        if(scenario && !scenario.value.includes(msg)) {{
          scenario.value += "\\n" + msg;
        }}
      }}
    }}
    function resetChecklist(id, scenarioBlockId, testLabel) {{
      localStorage.removeItem('art-checklist-' + id);
      loadChecklist(id, scenarioBlockId, testLabel);
    }}
    window.addEventListener('DOMContentLoaded', function() {{
      document.querySelectorAll('.art-checklist').forEach(function(div) {{
        var id = div.id.replace('checklist-','');
        var scenarioBlockId = div.getAttribute('data-scenario');
        var testLabel = div.getAttribute('data-label');
        loadChecklist(id, scenarioBlockId, testLabel);
        div.querySelectorAll('input[type=checkbox]').forEach(function(chk) {{
          chk.onchange = function() {{ saveChecklist(id, scenarioBlockId, testLabel); }};
        }});
      }});
    }});
  </script>
</head>
<body>
<div class="card">
  <h1>Alert: {escape(technique_name)}</h1>
  <div class="meta"><b>Technique ID:</b> {escape(tid)}</div>
  <div class="tactic section"><b>Tactics:</b> {escape(tactic_str)}</div>
  <div class="status section"><b>Status:</b> ART / do walidacji</div>
  <div class="scenario-block">
    <b>Twój opis scenariusza:</b><br>
    <textarea id="scenarioBlock" rows="7" readonly>
Tutaj wpisz opis scenariusza lub uzupełnij po testach.
    </textarea>
  </div>
  <div style='background:#eaf4ff;border-radius:8px;padding:15px 16px;margin-top:25px;'>
    <b>Atomic Red Team – dostępne testy dla tej techniki:</b>
    <div style="margin-bottom:10px;">
      <span class="badge badge-total">{total} testów</span>
      <span class="badge badge-ps">{ps} PowerShell</span>
      <span class="badge badge-cmd">{cmd} CMD</span>
      <a href='https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/{escape(tid)}' target='_blank' style="float:right;">Zobacz na GitHubie</a>
    </div>
"""

    # Dodaj testy jako accordion
    for idx, t in enumerate(atomic_tests, 1):
        uid = f"art{idx:02d}"
        test_label = escape(t["title"])
        html += f"""
    <div class="art-accordion">
      <button class="art-accordion-btn" onclick="toggleArtAccordion(this)">
        {art_badge(t["scripts"][0][0]) if t["scripts"] else ''}
        <b>{escape(t['title'])}</b>
        <span id="tested-badge-{uid}" class="badge badge-ok" style="display:none; float:right;">PRZETESTOWANE</span>
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
        # Cleanup
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
        # Checklist
        html += f"""
        <div class="art-checklist" id="checklist-{uid}" data-scenario="scenarioBlock" data-label="{test_label}">
          <label><input type="checkbox"> Uruchomiono test</label><br>
          <label><input type="checkbox"> Wykonano cleanup</label><br>
          <label><input type="checkbox"> Zdarzenie widoczne w Defenderze</label><br>
          <label><input type="checkbox"> Utworzono alert</label><br>
          <button onclick="resetChecklist('{uid}','scenarioBlock','{test_label}')">Resetuj</button>
        </div>
      </div>
    </div>
"""
    html += f"""
  </div>
  <div class="desc section"><b>MITRE Description:</b><br>{escape(mitre_desc) or '<i>(brak)</i>'}</div>
  <div class="link section"><b>MITRE Link:</b> <a href="{escape(mitre_link)}" target="_blank">{escape(mitre_link)}</a></div>
  <div class="author section"><b>Author:</b> {escape(author)}</div>
</div>
</body>
</html>
"""
    return html

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
        tid_match = re.search(r'\*\*(?:Technika|Technique ID):\*\*\s*([^\s\n]+)', content, re.IGNORECASE)
        tname_match = re.search(r'\*\*(?:Nazwa|Name):\*\*\s*([^\n*]+)', content, re.IGNORECASE)
        tactics_match = re.search(r'\*\*Taktyki:\*\*\s*([^\n*]+)', content, re.IGNORECASE)
        author_match = re.search(r'\*\*Autor:\*\*\s*([^\n*]+)', content, re.IGNORECASE)
        mitre_desc_match = re.search(r'\*\*MITRE Description:\*\*\s*([\s\S]*?)(?:\*\*|$)', content, re.IGNORECASE)
        mitre_link_match = re.search(r'(https://attack\.mitre\.org/techniques/[^\s\)]+)', content)
        tid = tid_match.group(1).strip().upper() if tid_match else "UNKNOWN"
        tname = tname_match.group(1).strip() if tname_match else "UNKNOWN"
        tactics = tactics_match.group(1).strip() if tactics_match else ""
        author = author_match.group(1).strip() if author_match else "Anon"
        mitre_desc = mitre_desc_match.group(1).strip() if mitre_desc_match else ""
        mitre_link = mitre_link_match.group(1).strip() if mitre_link_match else ""
        atomic_tests = get_atomic_tests_for_tid(tid)
        if not atomic_tests:
            continue
        # Tworzenie folderów/scenariuszy jak wcześniej
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
        # Nadpisz HTML pod nowy styl
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
    print("2) Merge PRO – generuj foldery/skrypty i czytelny raport HTML (PL)")
    wyb = input("Wybierz tryb (1/2): ").strip()
    if wyb == "1":
        atomic_coverage_matrix()
    elif wyb == "2":
        merge_pro()

if __name__ == "__main__":
    main()
