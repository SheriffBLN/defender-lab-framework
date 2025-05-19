# ❓ FAQ – Defender Lab Framework

---

## 🔁 Czy muszę od razu testować każdy scenariusz?

Nie. Framework pozwala tworzyć `scenarios/` z `status: "Pending"` – możesz planować i testować dopiero wtedy, gdy znajdziesz czas.

---

## ✅ Jakie są statusy w `tags.json`?

- `Pending` – scenariusz zaplanowany, ale jeszcze nietestowany
- `Audit` – działa w trybie audytu (np. ASR Audit Mode)
- `Tested` – scenariusz został wykonany i daje wykrycie/logi

---

## 🧪 Gdzie uruchamiam `attack.ps1`?

Tylko na maszynie testowej (np. Windows 11 z Defenderem w labie).  
Skrypt `03_run_scenario.py` wykonuje `attack.ps1` i zapisuje wynik do `logs/output.txt`.

---

## ⚙️ Co robi `merge_all_full.py`?

Odpala cały pipeline:
1. Wyciąga KQL z alertów
2. Waliduje `tags.json`
3. Tworzy `status.csv` z pokryciem technik
4. Generuje raport HTML
5. Tworzy JSON dla MITRE Navigatora

---

## 📦 Czy framework działa jeśli tylko część rzeczy jest opisana?

Tak! Nie musisz mieć od razu:
- pliku `.md` w `alerts/`
- huntingu w `.kql`
- kompletnego `detection.md`

Wystarczy, że stworzysz `tags.json`, nawet z `Pending` i folder będzie śledzony.

---

## 📤 Po co GitHub Pages?

- Umożliwia wystawienie raportu HTML i dokumentacji jako strona online
- Można wstawić do CV, portfolio, udostępnić z linka
- Pliki z `docs/` są automatycznie publikowane jako strona

---

## 🧠 Czy mogę dopisywać techniki ręcznie?

Oczywiście. Możesz tworzyć folder `Txxxx_Opis`, edytować `tags.json`, opisać `attack.ps1` – framework to wyłapie.

---

## 💬 Co jeśli wpiszę zły `status`?

Skrypt `validate_tags.py` ostrzeże Cię, że np. `status: "Done"` nie jest poprawny. Dozwolone: `Pending`, `Audit`, `Tested`.

---

## 🧩 Jak najlepiej z niego korzystać?

1. Używaj `00_generate_scenario.py` do tworzenia scenariuszy
2. Dokumentuj alerty i hunting, kiedy masz czas
3. Oznaczaj `status` zgodnie z etapem pracy
4. Odpalaj `merge_all_full.py` regularnie, żeby raport i mapping były aktualne
