import os
import re
import html

DEFAULT_AUTHOR = "APT Matrix Generator"

def md_to_html_basic(md_text):
    """Podstawowy konwerter markdown do HTML (nagłówki, bold, linki, listy)"""
    html_lines = []
    for line in md_text.splitlines():
        line = html.escape(line)
        # Nagłówki
        line = re.sub(r'^###### (.*)', r'<h6>\1</h6>', line)
        line = re.sub(r'^##### (.*)', r'<h5>\1</h5>', line)
        line = re.sub(r'^#### (.*)', r'<h4>\1</h4>', line)
        line = re.sub(r'^### (.*)', r'<h3>\1</h3>', line)
        line = re.sub(r'^## (.*)', r'<h2>\1</h2>', line)
        line = re.sub(r'^# (.*)', r'<h1>\1</h1>', line)
        # Pogrubienie **...**
        line = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', line)
        # Linki [text](url)
        line = re.sub(r'\[(.*?)\]\((.*?)\)', r'<a href="\2" target="_blank">\1</a>', line)
        # Listy
        line = re.sub(r'^\s*-\s(.*)', r'<li>\1</li>', line)
        html_lines.append(line)
    html_block = "\n".join(html_lines)
    # Dodaj <ul> jeśli są <li>
    if '<li>' in html_block:
        html_block = re.sub(r'((?:<li>.*?</li>\n?)+)', r'<ul>\1</ul>\n', html_block, flags=re.DOTALL)
    # Paragrafy dla gołych linii
    html_block = re.sub(r'^(?!<h\d>|<ul>|<li>|<b>|<a)(.+)$', r'<p>\1</p>', html_block, flags=re.MULTILINE)
    return html_block

def extract_alert_fields_from_md(md_text):
    meta = {}
    meta_block = re.search(r'<!--(.*?)-->', md_text, re.DOTALL)
    if meta_block:
        meta_text = meta_block.group(1)
        for line in meta_text.splitlines():
            if ":" in line:
                key, val = line.split(":", 1)
                meta[key.strip().lower()] = val.strip()
    patterns = {
        "technique id": r'\*\*Technika:\*\*\s*([^\n*]+)|\*\*Technique ID:\*\*\s*([^\n*]+)',
        "technique name": r'\*\*Nazwa:\*\*\s*([^\n*]+)|\*\*Technique Name:\*\*\s*([^\n*]+)',
        "tactics": r'\*\*Taktyki:\*\*\s*([^\n*]+)|Tactics:\s*([^\n*]+)',
        "status": r'\*\*Status:\*\*\s*([^\n*]+)|Status:\s*([^\n*]+)',
        "author": r'\*\*Autor:\*\*\s*([^\n*]+)|Autor:\s*([^\n*]+)'
    }
    for key, pattern in patterns.items():
        res = re.search(pattern, md_text)
        if res:
            val = res.group(1) or res.group(2)
            if val:
                meta[key] = val.strip()
    mitre_link = re.search(r'(https://attack\.mitre\.org/techniques/[^\s\)]+)', md_text)
    mitre_link = mitre_link.group(1) if mitre_link else ""
    tname = re.search(r'# Alert: (.*)', md_text)
    tname = tname.group(1).strip() if tname else meta.get('technique name', '')
    after_header = md_text.split('\n', 1)[1] if '\n' in md_text else ""
    body_main = ""
    mitre_desc = ""
    if "---" in after_header:
        body_main = after_header.split("---", 1)[0].strip()
        rest = after_header.split("---", 1)[1]
    else:
        m = re.search(r'(\*\*Description:\*\*)', after_header)
        if m:
            body_main = after_header[:m.start()].strip()
        else:
            body_main = after_header.strip()
        rest = after_header[m.end():] if m else ""
    # Opis MITRE
    mitre_desc_match = re.search(r'\*\*Description:\*\*\s*([\s\S]+?)(?:\n\S|\Z)', md_text)
    if mitre_desc_match:
        mitre_desc = mitre_desc_match.group(1).strip()
    else:
        mitre_desc = ""
    tid = meta.get('technique id', '')
    tactic = meta.get('tactics', '')
    status = meta.get('status', '')
    author = meta.get('author', DEFAULT_AUTHOR)
    tname_full = meta.get('technique name', tname)
    return tid, tname_full, tactic, status, mitre_link, body_main, mitre_desc, author

def generate_html_card(tid, tname, tactic, status, mitre_link, body_main, mitre_desc, author):
    body_main_html = md_to_html_basic(body_main) if body_main else "<i>(brak)</i>"
    mitre_desc_html = md_to_html_basic(mitre_desc) if mitre_desc else "<i>(brak)</i>"
    html = f"""<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="UTF-8">
  <title>Alert: {tname}</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 2rem; background: #f6f7fb; }}
    .card {{ background: #fff; border-radius: 10px; box-shadow: 0 2px 6px #bbb; padding: 2rem; max-width: 700px; margin: auto; }}
    h1 {{ margin-top: 0; font-size: 2rem; }}
    .desc, .id, .link, .author, .tactic, .status {{ margin-bottom: 1.1em; }}
    .meta {{ font-size: .95em; color: #555; margin-bottom: .8em; }}
    .section {{ font-size: .99em; }}
    pre {{ background: #eee; padding: .7em 1em; border-radius: 5px; }}
    code {{ background: #f6f6f6; padding: 2px 5px; border-radius: 2px; }}
    ul {{ margin-left: 1.6em; }}
  </style>
</head>
<body>
<div class="card">
  <h1>Alert: {tname}</h1>
  <div class="meta"><b>Technique ID:</b> {tid}</div>
  <div class="tactic section"><b>Tactics:</b> {tactic}</div>
  <div class="status section"><b>Status:</b> {status}</div>
  <div class="desc section"><b>Scenario / Custom Description:</b><br>{body_main_html}</div>
  <div class="desc section"><b>MITRE Description:</b><br>{mitre_desc_html}</div>
  <div class="link section"><b>MITRE Link:</b> <a href="{mitre_link}" target="_blank">{mitre_link}</a></div>
  <div class="author section"><b>Author:</b> {author}</div>
</div>
</body>
</html>
"""
    return html

def convert_md_alerts_to_html(alerts_folder):
    for root, dirs, files in os.walk(alerts_folder):
        for filename in files:
            if filename.endswith(".md"):
                md_path = os.path.join(root, filename)
                html_path = md_path.replace(".md", ".html")
                with open(md_path, "r", encoding="utf-8") as f:
                    md_text = f.read()
                tid, tname, tactic, status, mitre_link, body_main, mitre_desc, author = extract_alert_fields_from_md(md_text)
                html_card = generate_html_card(tid, tname, tactic, status, mitre_link, body_main, mitre_desc, author)
                with open(html_path, "w", encoding="utf-8") as f:
                    f.write(html_card)
    print("[✓] Wszystkie pliki .md przekonwertowano na .html (ładny markdown, listy, nagłówki, linki, bold).")

if __name__ == "__main__":
    convert_md_alerts_to_html("alerts")
