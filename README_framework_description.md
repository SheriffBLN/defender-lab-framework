# Defender Lab Framework

Framework do tworzenia, testowania i dokumentowania scenariuszy detekcyjnych z mapowaniem na MITRE ATT&CK®. Projekt skupia się na środowisku Microsoft Defender for Endpoint oraz powiązanych komponentach systemu Windows i O365.

---

## 📁 Struktura repozytorium

```
defender-lab-framework/
├── alerts/                       # Opis detekcji i alertów (np. MDE)
│   └── identity-management/
├── hunting/                      # KQL, Sigma i inne reguły huntingowe
├── mapping/mitre-navigator/     # Mapowanie na ATT&CK + statusy
│   ├── techniques.csv
│   └── lab-detection-mapping.json
├── scenarios/                   # Scenariusze testowe z logami i detekcją
│   └── T1136.001_LocalAccountCreated/
├── tools/                       # Skrypty automatyzujące generowanie
│   ├── generate_scenario.py
│   ├── generate_status.py
│   └── generate_report.py
├── report/                      # Wygenerowane raporty (HTML)
└── README.md
```

---

##  Przebieg pracy (flow)

1.  Utwórz nowy scenariusz: `generate_scenario.py`
2.  Przeprowadź test / atak z `attack.ps1`
3.  Zbierz logi i opisz detekcję w `detection.md`
4.  Uzupełnij `tags.json` (technika, status, taktyki)
5.  Wygeneruj `techniques.csv`: `generate_status.py`
6.  Wygeneruj raport HTML: `generate_report.py`

---

##  Skrypty

### `generate_scenario.py`
Tworzy szablon folderu scenariusza.

```bash
python tools/generate_scenario.py --id T1136.001 --name LocalAccountCreated
```

---

### `generate_status.py`
Tworzy plik `techniques.csv` z podsumowaniem statusów i taktyk na podstawie `tags.json` w scenariuszach.

```bash
python tools/generate_status.py
```

---

### `generate_report.py`
Tworzy przejrzysty raport HTML z podziałem na taktyki, wykresem i linkami.

```bash
python tools/generate_report.py
```

---

##  Co jest zautomatyzowane?

 Automatyczne:
- Tworzenie struktury scenariusza
- Generowanie statusów (`techniques.csv`)
- Generowanie raportu HTML + wykresów
- Otwieranie raportu w przeglądarce

 Ręczne:
- Przeprowadzenie testu (`attack.ps1`)
- Wypełnienie `detection.md`
- Uzupełnienie `tags.json` (techniki, status, taktyki)
- Dodanie hunting queries do `hunting/`

---

##  Przykład `tags.json`

```json
{
  "id": "T1136.001",
  "name": "LocalAccountCreated",
  "tactics": ["Persistence", "Privilege Escalation"],
  "status": "Tested",
  "linked_rule": "1_local_account_created_deleted.md"
}
```

---

##  Statusy w `tags.json`

- `Pending` – jeszcze nie realizowany
- `Audit` – reguła działa w trybie monitoringu
- `Tested` – przetestowany w środowisku

---

##  Autor

Prepared by **Krzysztof Krzymowski** – defender-lab-framework  
MITRE ATT&CK® is a registered trademark of The MITRE Corporation.

