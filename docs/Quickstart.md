 # ⚡ Quickstart – Defender Lab Framework
 
 Chcesz szybko zacząć? Oto instrukcja krok po kroku:
 
**Uruchom główny skrypt**
   ```powershell
   python.exe .\tools\main.py
   ```

**Wybierz tryb pracy:**
- **SingleTechnique** – pojedyncze techniki, sumowane do wspólnej matrycy
- **APT Group** – tworzenie osobnej matrycy dla grupy APT
- **Update** – masowa aktualizacja na podstawie status.csv
- **APT Matrix z STIX** – generuje macierz na podstawie pliku STIX (`mapping/<APT>`, `report/<APT>`)
- **Global Coverage** – tworzy macierz z ostatnich 30 dni w `mapping/global_coverage` i `report/global_coverage`
- **AlertEvidence Matrix** – buduje raporty z `tools/helpers/AlertEvidence.csv` w katalogu `alert_evidence_reports`
- **Full Navigator Export** – dla każdego `mapping/*` tworzy plik `layer.json`
 
 **Podążaj za kreatorem:**  
 Framework poprowadzi Cię przez proces (dodawanie technik, nazw, statusów itp.)
 
 **Otwórz wygenerowane raporty:**
 - Raporty HTML znajdziesz w `/report/`
 - Matryce i mappingi w `/mapping/`
 - Alerty w `/alerts/`
 - Scenariusze w `/scenarios/`
