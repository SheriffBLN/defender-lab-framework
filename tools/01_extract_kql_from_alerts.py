import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALERTS_DIR = ROOT / "alerts"
OUTPUT_DIR = ROOT / "hunting"

def extract_kql_blocks():
    if not OUTPUT_DIR.exists():
        OUTPUT_DIR.mkdir(parents=True)

    extracted = 0
    processed = 0

    for path in ALERTS_DIR.rglob("*.md"):
        lines = path.read_text(encoding="utf-8").splitlines()
        inside_kql = False
        buffer = []
        matches = []

        for line in lines:
            if line.strip().lower().startswith("```kql"):
                inside_kql = True
                buffer = []
                continue
            if inside_kql and line.strip().startswith("```"):
                inside_kql = False
                matches.append("\n".join(buffer))
                buffer = []
                continue
            if inside_kql:
                buffer.append(line)

        if matches:
            for idx, block in enumerate(matches):
                base_name = path.stem
                out_name = f"{base_name}_{idx+1}.kql" if len(matches) > 1 else f"{base_name}.kql"
                out_path = OUTPUT_DIR / out_name
                out_path.write_text(block.strip(), encoding="utf-8")
                print(f"[+] Extracted from {path.name} → {out_name}")
                extracted += 1
        else:
            print(f"[-] No KQL found in {path.name}")

        processed += 1

    print(f"[*] Processed {processed} alert files. Extracted {extracted} KQL blocks.")

if __name__ == "__main__":
    extract_kql_blocks()
