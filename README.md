# 🛡️ Defender Lab Framework

**Defender Lab Framework** to modularny framework do budowania, testowania oraz mapowania scenariuszy detekcyjnych w środowisku **Microsoft Defender for Endpoint (MDE)** oraz do automatycznego generowania raportów, warstw MITRE ATT&CK® Navigator, plików do huntingu i dokumentacji.

---

## 🔎 Co znajdziesz w tym repozytorium?

Framework pozwala:
- tworzyć i rozwijać własne scenariusze detekcyjne,
- mapować techniki na MITRE ATT&CK®,
- generować gotowe warstwy do MITRE Navigatora,
- prowadzić dokumentację i automatyczne raportowanie (HTML),
- łatwo zarządzać statusami testów i detekcji (Pending / Audit / Tested).

---

## 📁 Struktura projektu

- defender-lab-framework/
- alerts/
- hunting/
- mapping/
- report/
- scenarios/
- tools/
- docs/
- Quickstart.md
- templates/
- defender-lab-framework-template.zip
- README.md




Szczegóły w [docs/Quickstart.md](docs/Quickstart.md) oraz [docs/Pipeline.md](docs/Pipeline.md).

---

## 🚀 Szybki start

1. **Uruchom główny skrypt**  
   W katalogu `/tools` znajdziesz `defender_lab.py` (lub `99_merge_all_for_apt.py`).  
   Uruchom poleceniem:
   ```powershell
   python .\tools\defender_lab.py

Podążaj za kreatorem
Wybierz tryb pracy (SingleTechnique / APT Group / Update). Kreator przeprowadzi Cię przez kolejne kroki.

Wyniki:

Raporty: /report/
Mappingi i warstwy: /mapping/
Alerty: /alerts/
Scenariusze: /scenarios/
Hunting queries: /hunting/
Pełna dokumentacja: /docs/

---

### 📦 Szybki start – czysty szablon repo

Jeśli chcesz zacząć od czystej, przygotowanej struktury folderów – pobierz starter ZIP:
[docs/templates/defender-lab-framework-template.zip](docs/templates/defender-lab-framework-template.zip)

Rozpakuj go lokalnie i postępuj zgodnie z instrukcjami z [Quickstart.md](../Quickstart.md).

---

## 🗂️ Dokumentacja

- [docs/Quickstart.md](docs/Quickstart.md) — szybki start, jak uruchomić i co generuje framework  
- [docs/Pipeline.md](docs/Pipeline.md) — szczegółowy opis pipeline’u  
- [docs/FAQ.md](docs/FAQ.md) — pytania, porady, dobre praktyki  
- [docs/Instrukcja update.md](docs/Instrukcja%20update.md) — jak aktualizować statusy/scenariusze  

---

##♻️ Aktualizowanie statusów/scenariuszy

Możesz łatwo masowo aktualizować statusy/scenariusze:

- Edytuj `/mapping/NAZWA/status.csv` (np. zmień status na `Tested`, `Audit` lub `Pending`)
- Użyj trybu **Update** (w kreatorze frameworka), aby zaktualizować raporty i macierz
- Szczegóły: [docs/Instrukcja update.md](docs/Instrukcja%20update.md)

---


##📬 Kontrybucja / Kontakt
Masz pomysł na nowe scenariusze lub chcesz ulepszyć framework? Otwórz issue lub PR na GitHubie!

---

##📜 Licencja
Projekt dostępny na licencji MIT.

---