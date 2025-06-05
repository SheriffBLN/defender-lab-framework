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
    <html><head><meta charset='utf-8'><title>DEMO: AlertEvidence</title></head><body>
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
    return re.sub(r'[\\/:"*?<>| ]', '_', value)

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

# --- KLUCZOWA FUNKCJA: matryca MITRE (technika w każdej taktyce!) ---
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
        '<div class="container">',
        f'<h1>{title or "🛡️ Macierz MITRE ATT&CK"}</h1>',
        f'<div style="margin:10px 0 18px 0; font-size:1.18em;">Matryca wygenerowana dla: <b>{apt_folder or ""}</b></div>',
        f'<p style="color:#557;">Wygenerowano: {now}</p>',
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
    # --- tabela statusów ---
    html.append('<h2>📊 Tabela statusów</h2>')
    html.append('<table class="matrix-table"><tr><th>Technique ID</th><th>Name</th><th>Tactics</th><th>Status</th><th>Liczba wystąpień</th><th>Author</th></tr>')
    for row in status_rows:
        status = row["Status"]
        html.append(
            f"<tr style='background:{STATUS_BG_COLORS.get(status, '#fff')};'>" +
            "".join(f"<td>{row.get(c,'')}</td>" for c in ["Technique ID","Name","Tactics","Status","Liczba wystąpień","Author"]) +
            "</tr>"
        )
    html.append("</table>")
    html.append("</div>")
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
        for row in reader:
            key = row.get(csv_field, "").strip()
            if key:
                by_group[key].append(row)

    print(f"\n[✓] Znaleziono {len(by_group)} unikalnych wartości pola '{group_field}'.\n")

    skipped = []
    total_generated = 0
    for value, rows in by_group.items():
        dir_name = GROUP_FIELDS[group_field]
        outdir = os.path.join(OUTDIR, dir_name)
        os.makedirs(outdir, exist_ok=True)
        safe_val = safe_filename(str(value))[:40]
        outpath = os.path.join(outdir, f"{safe_val}.html")

        # Wyciągnij unikalne techniki i taktyki dla heatmapy/statystyk
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

        # --- Parsowanie eventów i generowanie sekcji zdarzeń ---
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
            "<h2>Pełna lista zdarzeń (bez pustych kolumn)</h2>",
            r"""
<style>
    .hl { background: #fff89a !important; }
    #eventsTable th { position: sticky; top: 0; background: #f3f7fa; cursor:pointer; }
    #eventsTable th.sorted-asc:after { content: " \25B2"; color: #1976d2; }
    #eventsTable th.sorted-desc:after { content: " \25BC"; color: #1976d2; }
</style>
"""
        ]
        inputs_row = "".join(
            f"<td><input type='text' onkeyup='filterEventsTable({i})' placeholder='Szukaj...' style='width:98%; font-size:1em; padding:3px; border-radius:5px; border:1px solid #bbb;'></td>"
            for i in range(len(used_cols))
        )
        html.append(f"""
<label for="eventsTableSearch" style="font-size:1.12em;">🔍 Filtrowanie zdarzeń: </label>
<span style="color: #888; font-size: 1em;">(Możesz wpisać coś w kilka kolumn naraz)</span>
<div style='overflow-x:auto; max-width:95vw;'>
<table id='eventsTable' border='1' style='border-collapse:collapse; background:#f7fafd; font-size:1em;'>
<tr>{''.join(f"<th onclick='sortEventsTable({i})'>{c}</th>" for i, c in enumerate(used_cols))}</tr>
<tr>{inputs_row}</tr>
""")
        for r, addf in events:
            html.append("<tr>" + "".join(
                f"<td>{addf.get(c, r.get(c,''))}</td>" for c in used_cols
            ) + "</tr>")
        html.append("</table></div>")

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
            var xNum = parseFloat(xVal.replace(/[^0-9\.\-]/g, ''));
            var yNum = parseFloat(yVal.replace(/[^0-9\.\-]/g, ''));
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
