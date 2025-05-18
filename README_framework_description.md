# Defender Lab Framework – Opis Techniczny

## 🎯 Cel projektu

Ten framework służy do:
- tworzenia realistycznych scenariuszy ataków i detekcji,
- testowania zachowania Microsoft Defender for Endpoint,
- mapowania technik do MITRE ATT&CK®,
- generowania raportów pokrycia i dokumentacji bezpieczeństwa.

---

## 🧱 Komponenty

- `scenarios/` – atomic tests, detection + logs + tags
- `alerts/` – reguły alertowe (np. MDE, Splunk)
- `hunting/` – KQL, Sigma, YARA
- `mapping/` – warstwy Navigatora, statusy
- `tools/` – skrypty do automatyzacji (build, walidacja, raport)

---

## 🔁 Pipeline automatyczny

Skrypt `merge_all.py` wykonuje:

1. Walidację `tags.json` we wszystkich scenariuszach
2. Generuje `techniques.csv` do mapowania
3. Generuje interaktywny raport HTML
4. Automatycznie otwiera raport w przeglądarce

---

## 🧪 Przykład scenariusza

```
scenarios/T1136.001_LocalAccountCreated/
├── attack.ps1
├── detection.md
├── tags.json
└── logs/
```

`tags.json`:
```json
{
  "id": "T1136.001",
  "name": "LocalAccountCreated",
  "tactics": ["Persistence", "Privilege Escalation"],
  "status": "Tested",
  "linked_alert": "alerts/identity-management/1_local_account_created_deleted.md",
  "linked_hunting": "hunting/T1136_user_created.kql"
}
```

---

## 📊 Efekt końcowy

Interaktywny raport w `report/lab-detection-report.html` z:
- podziałem na taktyki ATT&CK
- kolorami statusów
- linkami do alertów i reguł
- wykresem pokrycia

---

## 🧠 Autor

Projekt: Krzysztof Krzymowski  
Repozytorium: [defender-lab-framework](https://github.com/SheriffBLN/defender-lab-framework)
