# ❓ FAQ – Defender Lab Framework

Często zadawane pytania i odpowiedzi dotyczące korzystania z frameworka.

---

## 🔁 Czy muszę od razu testować każdy scenariusz?

Nie. Możesz stworzyć katalog scenariusza ze statusem `Pending` i wrócić do jego przetestowania później. Framework działa nawet z niekompletnymi wpisami.

---

## ✅ Jakie statusy wpisuję w `tags.json`?

- `Pending` – scenariusz zaplanowany, ale jeszcze nietestowany
- `Audit` – działa w trybie audytu (np. ASR Audit Mode)
- `Tested` – scenariusz został wykonany i zadziałało wykrycie / logi

---

## 🧪 Gdzie uruchamiam `attack.ps1`?

Na maszynie testowej z Defenderem (np. Windows 11 lab). Możesz użyć skryptu:

```bash
python tools/03_run_scenario.py --id T1136.001
```

Zapisze wynik do `logs/output.txt` wewnątrz katalogu scenariusza.

---

## ⚙️ Co dokładnie robi `merge_all_full.py`?

To skrypt, który wykonuje całą automatyzację w jednym kroku:

1. Wyciąga zapytania KQL z alertów (`alerts/`)
2. Waliduje strukturę tagów (`tags.json`)
3. Tworzy status pokrycia (plik CSV)
4. Generuje raport HTML (do przeglądarki)
5. Eksportuje warstwę do MITRE Navigatora (JSON)

---

## 📦 Czy mogę mieć niekompletne dane w scenariuszu?

Tak. Wystarczy plik `tags.json`. Nie musisz mieć:

- alertu (`.md` w `alerts/`)
- huntingu (`.kql`)
- pełnego opisu detekcji (`detection.md`)

Framework pozwala uzupełniać elementy w dowolnym tempie.

---

## 🌐 Po co GitHub Pages?

Jeśli opublikujesz raport (`report/index.html`) przez GitHub Pages, możesz:

- dzielić się wynikami pokrycia ATT&CK z innymi
- użyć raportu jako portfolio lub dokumentacji
- przeglądać pokrycie detekcji bez uruchamiania frameworka

---

## 🧠 Jakie są dobre praktyki przy tworzeniu scenariuszy?

- Testuj realistyczne techniki (np. techniki persistence, execution)
- Staraj się zmapować je do co najmniej jednej reguły (`linked_alert`)
- Nie musisz od razu pisać wszystkiego – dodaj `Pending` i wróć później
- W `tags.json` wpisuj prawdziwe ID technik, np. `T1547.001`

---

## 📬 Chcę dodać swój scenariusz – co dalej?

Super! Możesz:

1. Sforkować repozytorium i dodać swój scenariusz w katalogu `scenarios/`
2. Użyć skryptu `00_generate_scenario.py`, by stworzyć szablon
3. Wypełnić `tags.json`, dodać `attack.ps1`, i (opcjonalnie) opis

Gotowe? Zrób Pull Request – chętnie go przejrzę i połączę 🙌

---
