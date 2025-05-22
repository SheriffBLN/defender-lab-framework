import os
import json

def main():
    print("[00b] Tworzenie struktury folderów...")
    with open("tools/input_context.json", encoding="utf-8") as f:
        context = json.load(f)
    bases = ["alerts", "hunting", "mapping", "scenarios", "report"]
    apt = context["apt_name"]
    for base in bases:
        base_path = os.path.join(base, apt)
        os.makedirs(base_path, exist_ok=True)
        if base != "report":
            for tech in context["techniques"]:
                tid = tech["technique_id"]
                os.makedirs(os.path.join(base_path, tid), exist_ok=True)
    print("[00b] Struktura utworzona.")

if __name__ == "__main__":
    main()
