# 🛠️ Instrukcja użycia Defender Lab Framework

Framework służy do tworzenia scenariuszy testowych dla Microsoft Defender for Endpoint, ich dokumentowania, walidowania oraz automatycznego generowania statusów i raportów.

---

## 🧭 Krok po kroku

### 0. 🧱 Utwórz nowy scenariusz

```bash
python tools/00_generate_scenario.py --id T1136.001 --name LocalAccountCreated
```

---

### 1. 🔔 Tworzenie alertu (ręcznie)
- Utwórz plik `.md` w `alerts/`
- Nazwij go np. `1_local_account_created_deleted.md`
- Dodaj blok KQL:
    ````markdown
    ```kql
    DeviceEvents
    | where ActionType == "UserAccountCreated"
    ```
    ````

---

### 2. 📥 Wyciągnięcie KQL z alertów
```bash
python tools/01_extract_kql_from_alerts.py
```
- Tworzy pliki `.kql` w `hunting/`
- Na podstawie bloków z ` ```kql ... ``` `

---

### 3. ✅ Walidacja `tags.json`
```bash
python tools/02_validate_tags.py
```
- Sprawdza czy każdy scenariusz zawiera poprawne:
  - `id`, `name`, `tactics`, `status`, `linked_alert`, `linked_hunting`

---

### 4. ⚙️ Uruchomienie `attack.ps1` (na maszynie testowej z Defenderem)
```bash
# URUCHAMIAJ TYLKO NA MASZYNIE TESTOWEJ Z WINDOWS 11
python tools/03_run_scenario.py --id T1136.001
```
- Wykonuje `attack.ps1` dla wybranego scenariusza (np. z `scenarios/Txxxx/`)
- Zapisuje log do `logs/output.txt`

---

### 5. 📊 Generowanie statusów i raportów
```bash
python tools/04_generate_status.py
python tools/05_generate_report.py
```
- Tworzy `mapping/mitre-navigator/status.csv`
- Tworzy `report/lab-detection-report.html`

---

### 6. 🗺️ Export do warstwy Navigator
```bash
python tools/06_generate_navigator_json.py
```
- Tworzy plik `.json` z aktualnym stanem pokrycia

---

### ✅ Pełna automatyzacja
Zamiast wszystkich kroków osobno:
```bash
python tools/merge_all_full.py
```
- Wykonuje całość od walidacji po raport

---

## 📂 Struktura plików

```bash
scenarios/
└── T1136.001_LocalAccountCreated/
    ├── attack.ps1
    ├── detection.md
    ├── logs/
    └── tags.json
```

---

## 📌 Przykład `tags.json`

```json
{
  "id": "T1136.001",
  "name": "LocalAccountCreated",
  "tactics": ["Persistence", "Privilege Escalation"],
  "status": "Tested",
  "linked_alert": "alerts/1_local_account_created_deleted.md",
  "linked_hunting": "hunting/1_local_account_created_deleted.kql"
}
```

---

## 👤 Autor

Krzysztof Krzymowski  
Projekt: defender-lab-framework
