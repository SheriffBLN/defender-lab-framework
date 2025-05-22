import os
import json

def main():
    print("[03] Generowanie scenariuszy testowych...")
    with open("tools/input_context.json", encoding="utf-8") as f:
        context = json.load(f)
    apt = context["apt_name"]
    for tech in context["techniques"]:
        tid = tech["technique_id"]
        scen = os.path.join("scenarios", apt, tid, f"{tid}_scenario.md")
        tags = os.path.join("scenarios", apt, tid, "tags.json")
        content = (
            f"# Scenariusz testowy – {tid}\n\n"
            f"## Symulacja ataku\nOpis: Symulacja techniki {tid} – {tech['technique_name']}.\n\n"
            "## Detekcja\n"
            f"Oczekiwany alert: `{tid}_alert.md`\n\n"
            "## Oczekiwany efekt\n"
            f"Technika powinna zostać wykryta. Taktyki: {', '.join(tech['tactics'])}.\n"
        )
        with open(scen, "w", encoding='utf-8') as f:
            f.write(content)
        tag_data = {
            "id": tid,
            "name": tech['technique_name'],
            "tactics": tech['tactics'],
            "status": context['status'],
            "linked_rule": f"alerts/{apt}/{tid}/{tid}_alert.md"
        }
        with open(tags, "w", encoding='utf-8') as f:
            json.dump(tag_data, f, indent=4)
    print("[03] Scenariusze i tags.json wygenerowane.")

if __name__ == "__main__":
    main()
