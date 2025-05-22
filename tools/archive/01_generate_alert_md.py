import os
import json

# Ustawiamy ścieżkę bazową na katalog główny repo (nie tools/)
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
TEMPLATE_PATH = os.path.join(BASE_DIR, "tools", "helpers", "report_template.md")

def load_template(path=TEMPLATE_PATH):
    with open(path, encoding='utf-8') as f:
        return f.read()

def fill_template(template, data):
    out = template
    for key, value in data.items():
        out = out.replace('{{' + key + '}}', str(value))
    return out

def main():
    # Załaduj input_context.json z katalogu tools/
    context_path = os.path.join(BASE_DIR, "tools", "input_context.json")
    if not os.path.exists(context_path):
        print("[!] Brak pliku input_context.json")
        return
    with open(context_path, encoding="utf-8") as f:
        context = json.load(f)

    apt = context["apt_name"]
    template = load_template()
    for tech in context["techniques"]:
        tid = tech["technique_id"]
        alert_path = os.path.join(BASE_DIR, "alerts", apt, tid, f"{tid}_alert.md")

        data = {
            "title": tech['technique_name'],
            "technique_id": tid,
            "technique_name": tech['technique_name'],
            "tactics": ', '.join(tech['tactics']),
            "status": context['status'],
            "author": context['author'],
            "kql_queries": "",
            "test_cmd": "",
            "test_ps": "",
            "triage_tips": "Sprawdź inicjujący proces, użytkownika i źródło logu.",
            "detection_table": "| MDE | DeviceEvents | 4720 | UserAccountCreated |"
        }
        content = fill_template(template, data)
        os.makedirs(os.path.dirname(alert_path), exist_ok=True)
        with open(alert_path, "w", encoding="utf-8") as f:
            f.write(content)
    print("[01] Alerty z szablonu helpers/report_template.md wygenerowane.")

if __name__ == "__main__":
    main()
