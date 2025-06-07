import os
import csv
import re
import json
import sys
from datetime import datetime
from collections import defaultdict, Counter

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
    if count <= 0:
        return "#e0e0e0"
    ranges = [10, 19, 29, 39, 49]
    colors = [
        "#ffffb3",  # 1-10
        "#ffd480",  # 11-19
        "#ffa366",  # 20-29
        "#ff704d",  # 30-39
        "#c653ff",  # 40-49
        "#6f42c1",  # 50+
    ]
    for limit, col in zip(ranges, colors):
        if count <= limit:
            return col
    return colors[-1]

ALERT_EVIDENCE_CSV = "tools/helpers/AlertEvidence.csv"
ENTERPRISE_CSV = "tools/enterprise_attack.csv"
OUTDIR = "alert_evidence_reports"

GROUP_FIELDS = {
    "RemoteIP": "Adres IP (RemoteIP)",
    "User": "Użytkownik (AccountName)",
    "Host": "Komputer (DeviceName)",
    "Application": "Aplikacja (FileName)"
}
FIELD_TO_CSV = {
    "RemoteIP": "RemoteIP",
    "User": "AccountName",
    "Host": "DeviceName",
    "Application": "FileName"
}
TIMELINE_GROUPS = {"RemoteIP", "User", "Host"}

def check_files_exist():
    print("\n[DIAGNOSTYKA] Sprawdzam środowisko:")
    print(f"Python: {sys.version}")
    print(f"CWD: {os.getcwd()}")
    missing = []
    for path in [ALERT_EVIDENCE_CSV, ENTERPRISE_CSV]:
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
    print("\n[DEMO MODE] Przykładowa matryca dla demo_user:")
    demo_dir = os.path.join(OUTDIR, "DEMO")
    os.makedirs(demo_dir, exist_ok=True)
    outpath = os.path.join(demo_dir, "demo_user.html")
    html = """
    <html><head><meta charset='utf-8'><title>DEMO: AlertEvidence</title></head><body style='font-family:Segoe UI,Arial,sans-serif;'>
    <h1>Raport AlertEvidence DEMO</h1>
    <p>To jest widok demonstracyjny na podstawie przykładowych danych.</p>
    <ul>
        <li>AccountName: demo_user</li>
        <li>DeviceName: host-01</li>
        <li>FileName: powershell.exe</li>
        <li>RemoteIP: 192.168.0.1</li>
    </ul>
    <h2>Techniki</h2>
    <table border=1>
    <tr><th>Technique ID</th><th>Name</th><th>Tactics</th><th>Status</th><th>Liczba wystąpień</th></tr>
    <tr><td>T1059.001</td><td>PowerShell</td><td>execution</td><td>Tested</td><td>1</td></tr>
    </table>
    <div style="color:#888;">(tu byłaby pełna macierz/heatmapa jak w oryginalnym layoucie)</div>
    </body></html>
    """
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[✓] Demo raport dostępny w {outpath}")
    input("\nNaciśnij ENTER, aby zakończyć...")
    sys.exit(0)

def safe_filename(value):
    return re.sub(r'[\\/:\"*?<>| ]', '_', value)

def extract_technique_id(val):
    if not val:
        return []
    if val.startswith("[") and val.endswith("]"):
        found = re.findall(r"\(T\d{4}(?:\.\d{3})?\)", val)
        if found:
            return [tid[1:-1] for tid in found]
        found = re.findall(r"T\d{4}(?:\.\d{3})?", val)
        if found:
            return found
        return []
    if re.match(r"T\d{4}(?:\.\d{3})?$", val.strip()):
        return [val.strip()]
    return []

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

def load_techniques_db():
    db = {}
    with open(ENTERPRISE_CSV, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            tid = row["ID"].strip().upper()
            db[tid] = {
                "name": row["Name"].strip(),
                "tactics": [t.strip() for t in row["Tactics"].split(",") if t.strip()]
            }
    return db

def generate_status_rows(rows, group_field, value, techniques_db):
    tech_counts = Counter()
    for r in rows:
        tids = extract_technique_id(r.get("AttackTechniques") or "")
        for tid in tids:
            tech_counts[tid] += 1
    status_rows = []
    for tid, count in tech_counts.items():
        t = techniques_db.get(tid, {})
        status_rows.append({
            "Technique ID": tid,
            "Name": t.get("name", tid),
            "Tactics": ", ".join(t.get("tactics", [])),
            "Status": "Tested",
            "Liczba wystąpień": str(count),
            "Author": "AlertEvidence Matrix"
        })
    return status_rows

def highlight_alertid(val):
    if not val or not val.strip():
        return ""
    url = f"https://security.microsoft.com/alerts/{val.strip()}"
    return f"<a href='{url}' style='color:#1976d2; font-weight:bold;' target='_blank' title='Otwórz alert w Microsoft 365 Defender'>{val}</a>"

# --- ACCORDION: zwijane/rozwijane sekcje ---
def accordion_block(title, content, block_id):
    return f"""
<div class="accordion">
  <button class="accordion-btn" onclick="toggleAccordion('{block_id}')">{title}</button>
  <div class="accordion-content" id="{block_id}">{content}</div>
</div>
<style>
.accordion-btn {{
  background: #f1f5fb;
  color: #1976d2;
  cursor: pointer;
  padding: 12px 20px;
  width: 100%;
  border: none;
  text-align: left;
  outline: none;
  font-size: 1.12em;
  border-radius: 7px;
  margin-top: 18px;
  margin-bottom: 0;
  box-shadow: 0 1px 4px #e6e6e6;
  transition: background 0.2s;
}}
.accordion-btn:hover {{ background: #e3eaf4; }}
.accordion-content {{
  display: none;
  padding: 0.5em 1.1em 1.2em 1.1em;
  background: #fafbff;
  border: 1px solid #e0e0e0;
  border-radius: 0 0 7px 7px;
  margin-bottom: 2em;
  margin-top: 0;
}}
</style>
<script>
function toggleAccordion(id) {{
  var x = document.getElementById(id);
  if (x.style.display === "block") x.style.display = "none";
  else x.style.display = "block";
}}
</script>
"""

def generate_timeline(events, techniques_db):
    def parse_dt(r):
        for fld in ["Timestamp", "DetectionTimeUtc", "CreationTimeUtc"]:
            v = r.get(fld)
            if v:
                try:
                    return datetime.fromisoformat(v.replace("Z", ""))
                except Exception:
                    continue
        return datetime.min
    events_sorted = sorted(events, key=lambda x: parse_dt(x[0]))
    out = ['''
<div class="timeline-container">
  <div class="timeline-line"></div>
''']
    for r, addf in events_sorted:
        dt = r.get("Timestamp") or r.get("DetectionTimeUtc") or r.get("CreationTimeUtc") or ""
        tid = extract_technique_id(r.get("AttackTechniques") or "")
        technique = tid[0] if tid else ""
        tdata = techniques_db.get(technique, {})
        tname = tdata.get("name", technique)
        tactics = ", ".join(tdata.get("tactics", []))
        status = "Tested"
        cmd = addf.get("CommandLine") or addf.get("ImageFile") or ""
        alertid = r.get("AlertId")
        if alertid and ("?" in alertid or alertid.startswith("https://")):
            alert_link = f"<a href='{alertid}' target='_blank' style='color:#1976d2;font-weight:bold;' title='Otwórz alert'>{alertid}</a>"
        elif alertid:
            alert_link = highlight_alertid(alertid)
        else:
            alert_link = ""
        out.append(f"""
  <div class="timeline-event" style="background:{STATUS_BG_COLORS.get(status, '#d7eaf3')};">
    <div class="timeline-date">{dt}</div>
    <div class="timeline-title">{tname} <span style='color:#888;font-size:.97em;'>({technique})</span></div>
    <div class="timeline-tactics" style='color:#666;font-size:.95em;'>{tactics}</div>
    {'<div class="timeline-cmd">cmd: <span style="color:#1976d2;">'+cmd+'</span></div>' if cmd else ""}
    <div class="timeline-alertid">{alert_link}</div>
  </div>
""")
    out.append("</div>")
    out.append("""
<style>
.timeline-container { position:relative; margin:30px 0 60px 0; padding-left:42px; }
.timeline-line { position:absolute; left:13px; top:0; bottom:0; width:6px; background:#e3eaf4; border-radius:3px; }
.timeline-event {
    position:relative;
    margin-bottom:27px;
    padding:15px 20px 13px 22px;
    border-radius:10px;
    box-shadow:1px 4px 16px #e3e3e3;
    min-width:330px;
    max-width:600px;
}
.timeline-date { font-size:1.09em; font-weight:600; color:#1456a6; margin-bottom:3px; }
.timeline-title { font-size:1.15em; font-weight:700; margin-bottom:1px; }
.timeline-tactics { font-size:.99em; margin-bottom:2px; }
.timeline-cmd { font-size:.99em; color:#888; }
.timeline-alertid { font-size:1.01em; margin-top:4px; }
.timeline-event:before {
    content:"";
    position:absolute;
    left:-29px; top:22px;
    width:22px; height:22px;
    border-radius:11px;
    background:#fff;
    border:3px solid #1976d2;
    z-index:1;
}
</style>
""")
    return "\n".join(out)

def generate_matrix_html(status_rows, title, apt_folder):
    matrix = defaultdict(list)
    for r in status_rows:
        tactics = [t.strip().lower().replace(" ", "-") for t in r["Tactics"].split(",") if t.strip()]
        for t in tactics:
            if t in TACTICS_ORDER:
                matrix[t].append(r)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = [
        "<style>",
        "body { font-family: Segoe UI, Arial, sans-serif; }",
        ".container { max-width:1180px; margin:0 auto; }",
        ".matrix-table { border-collapse:collapse; width:100%; margin-bottom:28px; }",
        ".matrix-table th { background:#dbeafe; color:#1e293b; padding:7px 0; font-size:1.07em; border:1px solid #e3e3e3; }",
        ".matrix-table td { vertical-align:top; border:1px solid #e3e3e3; min-width:94px; padding:2px; }",
        ".matrix-technique { border-radius:7px; box-shadow:1px 2px 8px #e6e6e6;margin:7px 0; padding:7px 7px 5px 7px; font-size:.97em; font-weight:500; background:#fff; }",
        ".badge { padding:2px 12px 2px 12px; border-radius:8px; color:#fff; font-size:.92em; font-weight:700; letter-spacing:.05em; display:inline-block; }",
        ".badge-Tested { background:%s; }" % BADGE_COLORS["Tested"],
        ".badge-Audit { background:%s; color:#333 !important; }" % BADGE_COLORS["Audit"],
        ".badge-Pending { background:%s; }" % BADGE_COLORS["Pending"],
        ".badge-Disabled { background:%s; color:#222 !important; }" % BADGE_COLORS["Disabled"],
        ".badge-Suppressed { background:%s; color:#222 !important; }" % BADGE_COLORS["Suppressed"],
        "</style>",
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
        for row in matrix.get(tactic, []):
            status = row["Status"]
            bg = STATUS_BG_COLORS.get(status, "#fff")
            html.append(
                f'<div class="matrix-technique" style="background:{bg};">'
                f'<b>{row["Technique ID"]}</b><br>{row["Name"]}'
                f'<br><span class="badge badge-{status}">{status}</span>'
                f'<br><span style="font-size:0.95em; color:#565;">Liczba wystąpień: <b>{row.get("Liczba wystąpień","-")}</b></span>'
                '</div>'
            )
        html.append("</td>")
    html.append("</tr></table>")
    return "\n".join(html)

def generate_heatmap_matrix_html(status_rows, title, apt_folder):
    tech_counts = {row["Technique ID"]: int(row.get("Liczba wystąpień", 0)) for row in status_rows}
    matrix = defaultdict(list)
    for r in status_rows:
        tactics = [t.strip().lower().replace(" ", "-") for t in r["Tactics"].split(",") if t.strip()]
        for t in tactics:
            if t in TACTICS_ORDER:
                matrix[t].append(r)
    html = [
        '<h2>🔥 Heatmapa wyzwolonych technik</h2>',
        '<table class="matrix-table"><tr>'
    ]
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
        <span style="background:#ffffb3; padding:2px 8px; margin-right:8px;">1-10</span>
        <span style="background:#ffd480; padding:2px 8px; margin-right:8px;">11-19</span>
        <span style="background:#ffa366; padding:2px 8px; margin-right:8px;">20-29</span>
        <span style="background:#ff704d; padding:2px 8px; margin-right:8px;">30-39</span>
        <span style="background:#c653ff; padding:2px 8px; margin-right:8px;">40-49</span>
        <span style="background:#6f42c1; padding:2px 8px; margin-right:8px;">50+</span>
    </div>
    """)
    return "\n".join(html)

def main():
    print("\n=== AlertEvidence Matrix (layout DefenderLab – niezależny kod) ===\n")
    missing = check_files_exist()
    if missing:
        print("\n[!] Brak wymaganych plików: ", ", ".join(missing))
        demo = input("Czy uruchomić DEMO MODE? (t/n): ").strip().lower()
        if demo == "t":
            run_demo_mode()
        else:
            print("\nPrzerwano. Uzupełnij brakujące pliki i spróbuj ponownie.")
            sys.exit(1)

    print("Wybierz pole, po którym chcesz generować oddzielne macierze/raporty:\n")
    for i, (f, pretty) in enumerate(GROUP_FIELDS.items()):
        print(f"  {i+1}) {pretty}")
    try:
        group_idx = int(input("\nTwój wybór (1/2/3/4): "))
        group_field = list(GROUP_FIELDS.keys())[group_idx-1]
        csv_field = FIELD_TO_CSV[group_field]
    except Exception:
        print("Niepoprawny wybór – przerywam.")
        return

    try:
        min_tactics = int(input("\nPodaj minimalną liczbę unikalnych taktyk MITRE, by wygenerować raport (np. 3): ") or "3")
    except Exception:
        min_tactics = 3

    if not os.path.exists(ALERT_EVIDENCE_CSV):
        print(f"\n[!] Brak pliku: {ALERT_EVIDENCE_CSV}\n")
        return

    techniques_db = load_techniques_db()

    with open(ALERT_EVIDENCE_CSV, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        by_group = defaultdict(list)
        canonical = {}
        for row in reader:
            key = row.get(csv_field, "").strip()
            if key:
                key_lower = key.lower()
                by_group[key_lower].append(row)
                canonical.setdefault(key_lower, key)

    print(f"\n[✓] Znaleziono {len(by_group)} unikalnych wartości pola '{group_field}'.\n")

    value_filter = input("Podaj konkretną wartość (lub kilka oddzielonych przecinkiem), \naby wygenerować tylko dla niej/nich (ENTER = wszystkie): ").strip()
    selected_values = {v.strip().lower() for v in value_filter.split(',') if v.strip()} if value_filter else None

    skipped = []
    total_generated = 0
    for key_lower, rows in by_group.items():
        if selected_values and key_lower not in selected_values:
            continue
        value = canonical[key_lower]
        dir_name = GROUP_FIELDS[group_field]
        outdir = os.path.join(OUTDIR, dir_name)
        os.makedirs(outdir, exist_ok=True)
        base_name = safe_filename(str(value))[:40]
        outpath = os.path.join(outdir, f"{base_name}.html")
        counter = 1
        while os.path.exists(outpath):
            outpath = os.path.join(outdir, f"{base_name}_{counter}.html")
            counter += 1

        all_tactics = set()
        for r in rows:
            tids = extract_technique_id(r.get("AttackTechniques") or "")
            for tid in tids:
                t = techniques_db.get(tid)
                if t and t.get("tactics"):
                    all_tactics.update([x.strip().lower().replace(" ", "-") for x in t["tactics"]])
        if len(all_tactics) < min_tactics:
            skipped.append((value, len(all_tactics)))
            continue

        status_rows = generate_status_rows(rows, group_field, value, techniques_db)
        matrix_html = generate_matrix_html(status_rows, title="🛡️ Macierz MITRE ATT&CK", apt_folder=f"{group_field}={value}")
        heatmap_html = generate_heatmap_matrix_html(status_rows, title="🔥 Heatmapa MITRE", apt_folder=f"{group_field}={value}")

        events = []
        all_fields = set(rows[0].keys())
        add_keys = set()
        for r in rows:
            addf = parse_additional_fields(r.get("AdditionalFields", ""))
            add_keys.update(addf.keys())
            events.append((r, addf))

        nonempty_fields = set()
        for r, addf in events:
            for c, v in {**r, **addf}.items():
                if c == "AdditionalFields":
                    continue
                if v and str(v).strip():
                    nonempty_fields.add(c)
        used_cols = [c for c in all_fields if c in nonempty_fields]
        for c in add_keys:
            if c in nonempty_fields and c not in used_cols:
                used_cols.append(c)

        html = [
            f"<html><head><meta charset='utf-8'><title>{group_field}: {value}</title></head><body style='font-family:Segoe UI,Arial,sans-serif;'>",
            f"<h1>Raport AlertEvidence: {group_field} = {value}</h1>",
            f"<p>Data generowania: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
            f"<p>Liczba zdarzeń: <b>{len(rows)}</b></p>",
            f"<p><b>Liczba unikalnych taktyk MITRE:</b> <span style='color: #1976d2;'>{len(all_tactics)}</span></p>",
            matrix_html,
            heatmap_html,
        ]

        if group_field in TIMELINE_GROUPS:
            timeline_html = generate_timeline(events, techniques_db)
            html.append(accordion_block("🕒 Pokaż/ukryj oś czasu (timeline)", timeline_html, "timelineAccordion"))

        html.append("<h2>📊 Tabela statusów</h2>")
        html.append('<table class="matrix-table"><tr><th>Technique ID</th><th>Name</th><th>Tactics</th><th>Status</th><th>Liczba wystąpień</th><th>Author</th></tr>')
        for row in status_rows:
            status = row["Status"]
            html.append(
                f"<tr style='background:{STATUS_BG_COLORS.get(status, '#fff')};'>" +
                "".join(f"<td>{row.get(c,'')}</td>" for c in ["Technique ID","Name","Tactics","Status","Liczba wystąpień","Author"]) +
                "</tr>"
            )
        html.append("</table>")

        events_table_html = []
        events_table_html.append("<div style='overflow-x:auto; max-width:95vw;'>")
        events_table_html.append(f"<table id='eventsTable' border='1' style='border-collapse:collapse; background:#f7fafd; font-size:1em;'>")
        events_table_html.append("<tr>"+''.join(f"<th onclick='sortEventsTable({i})'>{c}</th>" for i, c in enumerate(used_cols))+"</tr>")
        events_table_html.append("<tr>"+ "".join(
            f"<td><input type='text' onkeyup='filterEventsTable({i})' placeholder='Szukaj...' style='width:98%; font-size:1em; padding:3px; border-radius:5px; border:1px solid #bbb;'></td>"
            for i in range(len(used_cols))
        )+"</tr>")
        for r, addf in events:
            events_table_html.append("<tr>" + "".join(
                f"<td>{highlight_alertid(addf.get(c, r.get(c,''))) if c=='AlertId' else addf.get(c, r.get(c,''))}</td>" for c in used_cols
            ) + "</tr>")
        events_table_html.append("</table></div>")
        html.append(accordion_block("📋 Pokaż/ukryj pełną listę zdarzeń", "\n".join(events_table_html), "eventsAccordion"))

        html.append(r"""
<script>
function filterEventsTable(colIdx) {
    var table = document.getElementById('eventsTable');
    var trs = table.getElementsByTagName('tr');
    var filters = [];
    var filterInputs = trs[1].getElementsByTagName('input');
    for (var i=0;i<filterInputs.length;i++){
        filters.push(filterInputs[i].value.toLowerCase());
    }
    for (var r=2; r<trs.length; r++) {
        var tds = trs[r].getElementsByTagName('td');
        var show = true;
        for (var c=0; c<filters.length; c++) {
            var cell = tds[c];
            var txt = cell.textContent || cell.innerText || '';
            cell.innerHTML = txt.replace(/<span class="hl">|<\/span>/g, '');
            if (filters[c] && txt.toLowerCase().indexOf(filters[c]) == -1) {
                show = false;
            }
        }
        if (show) {
            for (var c=0; c<filters.length; c++) {
                var cell = tds[c];
                var filter = filters[c];
                var txt = cell.innerHTML;
                if (filter) {
                    var re = new RegExp("(" + filter.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ")", "gi");
                    cell.innerHTML = txt.replace(re, '<span class="hl">$1</span>');
                }
            }
        }
        trs[r].style.display = show ? "" : "none";
    }
}
function sortEventsTable(col) {
    var table = document.getElementById("eventsTable");
    var switching = true, dir = "asc", switchcount = 0;
    var ths = table.getElementsByTagName('th');
    for(var i=0;i<ths.length;i++){ths[i].classList.remove("sorted-asc","sorted-desc");}
    while (switching) {
        switching = false;
        var rows = table.rows;
        for (var i = 2; i < (rows.length - 1); i++) {
            var shouldSwitch = false;
            var x = rows[i].getElementsByTagName("TD")[col];
            var y = rows[i + 1].getElementsByTagName("TD")[col];
            var xVal = x ? x.textContent || x.innerText : '';
            var yVal = y ? y.textContent || y.innerText : '';
            var xNum = parseFloat(xVal.replace(/[^0-9\\.\\-]/g, ''));
            var yNum = parseFloat(yVal.replace(/[^0-9\\.\\-]/g, ''));
            if (!isNaN(xNum) && !isNaN(yNum)) {
                if (dir == "asc" ? xNum > yNum : xNum < yNum) { shouldSwitch = true; break; }
            } else {
                if (dir == "asc" ? xVal.toLowerCase() > yVal.toLowerCase() : xVal.toLowerCase() < yVal.toLowerCase()) {
                    shouldSwitch = true; break;
                }
            }
        }
        if (shouldSwitch) {
            rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
            switching = true;
            switchcount ++;
        } else {
            if (switchcount == 0 && dir == "asc") {
                dir = "desc";
                switching = true;
            }
        }
    }
    ths[col].classList.add(dir == "asc" ? "sorted-asc" : "sorted-desc");
}
</script>
""")
        html.append("</body></html>")
        with open(outpath, "w", encoding="utf-8") as f:
            f.write("\n".join(html))
        print(f"[✓] {outpath}")
        total_generated += 1

    print(f"\n[✓] Wygenerowano {total_generated} raportów (tylko tam, gdzie >= {min_tactics} unikalnych taktyk MITRE).")
    if skipped:
        print(f"[i] Pominięto {len(skipped)} przypadków z mniejszą liczbą taktyk:")
        for val, num in skipped:
            print(f"    - {val}: {num} taktyk")

if __name__ == "__main__":
    main()
