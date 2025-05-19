# 🛠️ Instrukcja użycia Defender Lab Framework

Ten dokument prowadzi Cię krok po kroku przez cały proces: od utworzenia scenariusza, przez jego uruchomienie, aż po wygenerowanie raportu i mapy ATT&CK.

---

## 🧭 Krok po kroku

### 0. 🧱 Utwórz nowy scenariusz

```bash
python tools/00_generate_scenario.py --id T1136.001 --name LocalAccountCreated
```

To utworzy nowy folder w `scenarios/` z szablonem plików (`attack.ps1`, `detection.md`, `tags.json`, `logs/`).

---

### 1. 🔔 Stwórz plik alertu

Utwórz ręcznie plik `.md` w folderze `alerts/`, np.:

```
alerts/identity-management/1_local_account_created_deleted.md
```

Dodaj do niego zapytanie KQL w bloku:

```markdown
```kql
DeviceEvents
| where ActionType == "UserAccountCreated"
```
```

---

### 2. 📥 Wyciągnij KQL z alertów

```bash
python tools/01_extract_kql_from_alerts.py
```

Ten krok automatycznie tworzy pliki `.kql` w katalogu `hunting/` na podstawie wcześniej utworzonych alertów.

---

### 3. ✅ Sprawdź poprawność tagów

```bash
python tools/02_validate_tags.py
```

Walidacja sprawdza poprawność plików `tags.json` (czy zawierają pola `id`, `name`, `tactics`, `status`, `linked_alert` itd.).

---

### 4. ⚙️ Uruchom scenariusz na maszynie testowej

🛑 **Uruchamiaj tylko na maszynie testowej z Windows 11 + MDE!**

```bash
python tools/03_run_scenario.py --id T1136.001
```

Efekty działania zostaną zapisane w `logs/output.txt` w katalogu scenariusza.

---

### 5. 📌 Wygeneruj statusy testów

```bash
python tools/04_generate_status.py
```

Tworzy plik `status.csv` z listą wszystkich technik i ich aktualnym statusem (`Tested`, `Audit`, `Pending`).

---

### 6. 📊 Stwórz raport HTML

```bash
python tools/05_generate_report.py
```

Raport `report/index.html` zawiera:

- wykres pokrycia technik ATT&CK,
- tabelę z linkami do alertów i huntingu.

---

### 7. 🧭 Eksportuj warstwę do MITRE Navigator

```bash
python tools/06_generate_navigator_json.py
```

Tworzy plik `.json` w `mapping/mitre-navigator/` – gotowy do załadowania w [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

---

## 🔄 Alternatywnie: wszystko naraz

Możesz uruchomić cały pipeline jednym poleceniem:

```bash
python tools/merge_all_full.py
```

---

## 🧪 Przykład pełnego przepływu

1. Tworzysz nowy scenariusz `T1547.001_RunKey`.
2. W `attack.ps1` dodajesz PowerShell, który modyfikuje rejestr.
3. Piszesz regułę `.md` i dodajesz KQL.
4. Używasz `merge_all_full.py`, żeby zebrać wszystko w jeden raport.
5. Widzisz na mapie Navigatora, że technika `T1547.001` jest pokryta!

---

## 📌 Uwaga

Jeśli plik `tags.json` ma status `Pending`, nie musisz od razu dodawać całej detekcji – możesz wrócić później i go uzupełnić.

---

## 📬 Masz pytania?

Zajrzyj do `FAQ_FRAMEWORK.md` lub napisz do mnie na LinkedIn 💬
