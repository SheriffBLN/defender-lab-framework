from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALERTS_DIR = ROOT / "alerts"
OUTPUT_DIR = ROOT / "hunting"

def extract_kql_blocks():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    extracted = 0
    processed = 0

    for path in ALERTS_DIR.rglob("*.md"):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except Exception as e:
            print(f"[!] Błąd odczytu {path}: {e}")
            continue

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
                try:
                    out_path.write_text(block.strip(), encoding="utf-8")
                    print(f"[+] {path.name} → {out_name}")
                    extracted += 1
                except Exception as e:
                    print(f"[!] Błąd zapisu {out_name}: {e}")
        else:
            pass  # brak KQL = brak spamu

        processed += 1

    print(f"[*] Przetworzono {processed} plików alertów. Wyodrębniono {extracted} bloków KQL.")

if __name__ == "__main__":
    extract_kql_blocks()
