import os
import json

def main():
    print("[02] Wstawianie KQL do alertów...")
    with open("tools/input_context.json", encoding="utf-8") as f:
        context = json.load(f)
    apt = context["apt_name"]
    for tech in context["techniques"]:
        tid = tech["technique_id"]
        kql_file = os.path.join("hunting", apt, tid, f"{tid}.kql")
        alert_file = os.path.join("alerts", apt, tid, f"{tid}_alert.md")
        if os.path.exists(kql_file) and os.path.exists(alert_file):
            with open(kql_file, encoding='utf-8') as kf:
                kql = kf.read()
            with open(alert_file, "a", encoding='utf-8') as af:
                af.write("\n## KQL – hunting query\n```kql\n" + kql + "\n```\n")
    print("[02] KQL dodane.")

if __name__ == "__main__":
    main()
