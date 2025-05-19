import os
import csv
from datetime import datetime
from collections import defaultdict, Counter
import webbrowser

INPUT_CSV = "mapping/mitre-navigator/techniques.csv"
REPORT_HTML = "report/lab-detection-report.html"

STATUS_COLORS = {
    "Tested": "#d4edda",
    "Audit": "#fff3cd",
    "Pending": "#f8d7da"
}

def load_data():
    sections = defaultdict(list)
    status_counter = Counter()
    with open(INPUT_CSV, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            status_counter[row["Status"]] += 1
            for tactic in row["Tactics"].split(","):
                tactic = tactic.strip()
                if tactic:
                    sections[tactic].append(row)
    return dict(sorted(sections.items())), status_counter

def generate_html(data, status_counter):
    os.makedirs("report", exist_ok=True)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = sum(status_counter.values())

    html_parts = [
        "<!DOCTYPE html>",
        "<html><head><meta charset='UTF-8'>",
        "<title>Defender Lab Detection Report</title>",
        "<style>",
        "body { font-family: Arial, sans-serif; margin: 2em; }",
        "h1, h2 { color: #333; }",
        ".header { display: flex; align-items: center; }",
        ".logo { width: 60px; height: 60px; background: #ccc; margin-right: 1em; display: inline-block; }",
        ".footer { margin-top: 3em; font-style: italic; }",
        ".chart { width: 400px; height: 300px; margin-bottom: 2em; }",
        "table { width: 100%; border-collapse: collapse; margin-bottom: 2em; }",
        "th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }",
        "th { background-color: #f2f2f2; cursor: pointer; }",
        "</style>",
        "<script src='https://cdn.jsdelivr.net/npm/chart.js'></script>",
        "<script>",
        "function sortTable(n, tableID) {",
        "  var table = document.getElementById(tableID);",
        "  var switching = true, dir = 'asc', switchcount = 0;",
        "  while (switching) {",
        "    switching = false; var rows = table.rows;",
        "    for (var i = 1; i < (rows.length - 1); i++) {",
        "      var x = rows[i].getElementsByTagName('TD')[n];",
        "      var y = rows[i + 1].getElementsByTagName('TD')[n];",
        "      var shouldSwitch = (dir === 'asc') ? (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) : (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase());",
        "      if (shouldSwitch) {",
        "        rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);",
        "        switching = true; switchcount++; break;",
        "      }",
        "    }",
        "    if (switchcount === 0 && dir === 'asc') { dir = 'desc'; switching = true; }",
        "  }",
        "}",
        "</script>",
        "</head><body>",
        "<div class='header'><div class='logo'></div><div>",
        "<h1>Defender Lab Detection Report</h1>",
        f"<p><strong>Generated:</strong> {now}</p>",
        f"<p><strong>Total Scenarios:</strong> {total}</p>",
        "</div></div>",
        "<canvas class='chart' id='statusChart'></canvas>",
        "<script>",
        "const ctx = document.getElementById('statusChart');",
        "new Chart(ctx, {type: 'bar', data: {",
        f"labels: ['Tested', 'Audit', 'Pending'],",
        f"datasets: [{{label: 'Scenario Status', data: [{status_counter['Tested']}, {status_counter['Audit']}, {status_counter['Pending']}], backgroundColor: ['#d4edda', '#fff3cd', '#f8d7da']}}]",
        "}, options: {scales: {y: {beginAtZero: true}}}});",
        "</script>"
    ]

    for tactic, entries in data.items():
        table_id = f"table_{tactic.replace(' ', '_')}"
        html_parts.append(f"<h2>{tactic}</h2>")
        html_parts.append(f"<table id='{table_id}'><tr>")
        headers = ["#", "Technique ID", "Name", "Status", "Comment"]
        for i, header in enumerate(headers):
            html_parts.append(f"<th onclick=\"sortTable({i}, '{table_id}')\">{header}</th>")
        html_parts.append("</tr>")
        for idx, row in enumerate(entries, 1):
            bg = STATUS_COLORS.get(row["Status"], "#ffffff")
            comment = row["Comment"]
            if comment.endswith(".md"):
                comment = f"<a href='../alerts/identity-management/{comment}'>{comment}</a>"
            html_parts.append(f"<tr style='background-color: {bg};'>")
            html_parts.append(f"<td>{idx}</td><td>{row['Technique ID']}</td>")
            html_parts.append(f"<td title='Tactics: {row['Tactics']}'>{row['Name']}</td>")
            html_parts.append(f"<td>{row['Status']}</td><td>{comment}</td></tr>")
        html_parts.append("</table>")

    html_parts.append("<div class='footer'>Prepared by Krzysztof Krzymowski – defender-lab-framework</div></body></html>")

    with open(REPORT_HTML, "w", encoding="utf-8") as f:
        f.write("\n".join(html_parts))

    print(f"[+] HTML report saved to {REPORT_HTML}")
    webbrowser.open(REPORT_HTML)

if __name__ == "__main__":
    data, counter = load_data()
    generate_html(data, counter)
