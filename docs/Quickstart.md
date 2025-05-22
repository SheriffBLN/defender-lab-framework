# ⚡ Quickstart – Defender Lab Framework

Chcesz szybko zacząć? Oto instrukcja krok po kroku:

**Wejdź do katalogu tools/**  
   Tam znajduje się główny skrypt:  
   `99_merge_all_for_apt.py` lub `defender_lab.py`.

**Uruchom skrypt**  
   ```powershell
   python.exe .\tools\defender_lab.py

**Wybierz tryb pracy:**
- **SingleTechnique** – pojedyncze techniki, sumowane do wspólnej matrycy
- **APT Group** – tworzenie osobnej matrycy dla grupy APT
- **Update** – masowa aktualizacja na podstawie status.csv

**Podążaj za kreatorem:**  
Framework poprowadzi Cię przez proces (dodawanie technik, nazw, statusów itp.)

**Otwórz wygenerowane raporty:**
- Raporty HTML znajdziesz w `/report/`
- Matryce i mappingi w `/mapping/`
- Alerty w `/alerts/`
- Scenariusze w `/scenarios/`
