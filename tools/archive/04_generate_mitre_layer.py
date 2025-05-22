import os
import json

def main():
    print("[04] Tworzenie warstwy MITRE Navigator...")
    with open("tools/input_context.json", encoding="utf-8") as f:
        context = json.load(f)
    apt = context["apt_name"]
    techniques = [{"techniqueID": t['technique_id'], "score": 1} for t in context['techniques']]
    layer = {
        "name": f"{apt} – Lab Coverage",
        "version": "4.6",
        "domain": "enterprise-attack",
        "techniques": techniques
    }
    out = os.path.join("mapping", apt, "layer.json")
    with open(out, "w", encoding='utf-8') as f:
        json.dump(layer, f, indent=4)
    print(f"[04] Warstwa zapisana: {out}")

if __name__ == "__main__":
    main()
