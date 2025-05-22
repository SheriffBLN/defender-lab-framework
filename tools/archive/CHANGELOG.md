# 📝 CHANGELOG – Defender Lab Framework (Refaktoring tools/)

## 📅 Data: 2025-05-19
## 🔧 Zakres: pełny refaktoring folderu `tools/` + wydzielenie wspólnych funkcji

---

### 📂 Nowy plik pomocniczy
- `tools/shared_utils.py` – zawiera funkcje:
  - `load_json(path)`, `write_json(data, path)`
  - `get_all_scenario_folders()`, `get_scenario_by_id(id)`

---

### 📦 Skrypty zrefaktoryzowane

#### `00_generate_scenario.py`
- ID technik ujednolicone (`T1136.001` zamiast `1136.001`)
- Ochrona przed nadpisaniem istniejącego scenariusza
- Lepsze komunikaty i struktura katalogów

#### `01_extract_kql_from_alerts.py`
- Obsługa wielu bloków KQL w jednym pliku
- Lepsze logi i obsługa wyjątków odczytu
- Pomija alerty bez kodu

#### `02_validate_tags.py`
- Walidacja scenariuszy tylko na podstawie folderów z `tags.json`
- Czytelne komunikaty przy brakujących polach
- Użycie `shared_utils.get_all_scenario_folders()`

#### `03_run_scenario.py`
- Wyszukiwanie folderu po ID (np. `1136.001` → `T1136.001_...`)
- Logowanie kodu wyjścia PowerShella
- Obsługa błędu przy braku `attack.ps1`

#### `04_generate_status.py`
- Generuje `status.csv` z listą technik i przypisanym statusem
- Obsługuje oba pola: `linked_alert` i `linked_rule`

#### `05_generate_report.py`
- Raport HTML z kolorami dla `Tested`, `Audit`, `Pending`
- Sekcja z podsumowaniem liczbowym
- Linki do reguł jako `target="_blank"`

#### `06_generate_navigator_json.py`
- Generuje warstwę ATT&CK Navigator (`layer.json`)
- Dodatkowo eksportuje `techniques.csv`
- Kolory zdefiniowane dla statusów

#### `merge_all_full.py`
- Pipeline uruchamiający wszystkie kroki po kolei
- Komunikaty statusowe (`[✓]`, `[!]`)
- Zatrzymuje się przy pierwszym błędzie

---

### 🧳 Backup
- Stare wersje skryptów zachowane w: `tools/legacy_originals/`

---

### ✅ Status końcowy
Framework gotowy do:
- publikacji na GitHubie,
- integracji z GitHub Pages,
- prezentacji jako portfolio / projekt inżyniera detekcji.

