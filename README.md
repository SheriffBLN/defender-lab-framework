# 🛡️ Defender Lab Framework

Framework zaprojektowany z myślą o analitykach SOC, threat hunterach i inżynierach detekcji, którzy chcą tworzyć własne scenariusze testowe w środowisku Microsoft Defender for Endpoint (MDE). Pozwala na symulowanie ataków, wykrywanie ich w logach i mapowanie wyników na techniki MITRE ATT&CK®.

> 🔄 Dzięki automatyzacji, możesz wygodnie testować skuteczność swoich reguł EDR i generować raporty pokazujące pokrycie detekcji.

---

## 🎯 Główne cele

- 🧪 Tworzenie realistycznych scenariuszy ataku
- 🔍 Walidacja skuteczności reguł detekcji (np. MDE, Splunk)
- 🧭 Mapowanie technik na MITRE ATT&CK® (również warstwa Navigatora)
- 📊 Generowanie interaktywnego raportu HTML
- ⚙️ Automatyczne zarządzanie statusem testów i przypisaniami

---

## 🧱 Struktura projektu

```
defender-lab-framework/
├── scenarios/       # Scenariusze (atak, detekcja, logi, tagi)
├── alerts/          # Alerty i reguły bezpieczeństwa
├── hunting/         # Zapytania KQL, Sigma, YARA
├── mapping/         # Techniki MITRE + statusy + warstwa JSON
├── tools/           # Skrypty automatyzujące cały proces
├── report/          # Gotowy raport HTML i zrzuty ekranu
```

---

## 🔁 Pipeline (automatyzacja)

Główny skrypt `merge_all_full.py` wykonuje:

1. Walidację struktury `tags.json`
2. Ekstrakcję zapytań KQL z reguł alertów
3. Generowanie statusów i pliku CSV do mapowania
4. Eksport warstwy `.json` do MITRE Navigator
5. Tworzenie raportu HTML z wykresami i linkami

---

## 🧪 Jak wygląda scenariusz?

Przykład katalogu:

```
scenarios/T1136.001_LocalAccountCreated/
├── attack.ps1         # Skrypt wywołujący technikę (np. PowerShell)
├── detection.md       # Opis techniczny scenariusza
├── tags.json          # Metadane (taktyki, status, powiązania)
└── logs/              # Logi z wykrycia techniki
```

Minimalny `tags.json`:

```json
{
  "id": "T1136.001",
  "name": "LocalAccountCreated",
  "tactics": ["Persistence", "Privilege Escalation"],
  "status": "Tested",
  "linked_alert": "alerts/identity-management/1_local_account_created_deleted.md"
}
```

---

## 📌 Statusy technik (MITRE)

W scenariuszach przypisujesz status do każdej techniki:

- `Tested` – scenariusz został uruchomiony, wykryty i zmapowany
- `Audit` – reguła istnieje, ale nie została jeszcze przetestowana
- `Pending` – scenariusz jest zaplanowany lub częściowy

---

## 🧭 Mapowanie do MITRE ATT&CK

W folderze `mapping/mitre-navigator/` znajdziesz warstwę `.json`, którą możesz załadować do [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/). Kolory oznaczają status pokrycia.

---

## 📊 Raport interaktywny

Po uruchomieniu `merge_all_full.py`, framework generuje stronę `report/index.html`:

- Wykres pokrycia technik
- Tabela ze statusami i linkami do reguł
- Interfejs gotowy do publikacji przez GitHub Pages

---

## ℹ️ Dodatkowe pliki

- `INSTRUKCJA_FRAMEWORK.md` – szczegółowa instrukcja obsługi (PL)
- `FAQ_FRAMEWORK.md` – najczęstsze pytania
- `README_lab_setup.md` – jak zbudować własne środowisko testowe (PL + EN)

---

## 📬 Kontakt / autor

Projekt tworzony przez analityka SOC & detection engineera z pasją do automatyzacji i mapowania detekcji.

Masz pytania, chcesz się podzielić scenariuszem lub dać feedback?
→ Dodaj issue lub napisz na LinkedIn!

---

## ☕ Chcesz wesprzeć projekt?

Jeśli framework okazał się pomocny, rozważ:
**[Buy Me a Coffee ☕](https://buymeacoffee.com/yourlink)** – dziękuję! 🙏

---

## 📄 Licencja

MIT License. Wolno korzystać, rozwijać, dzielić się i forknąć 💻
