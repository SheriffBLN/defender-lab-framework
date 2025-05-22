# ❓ FAQ – Defender Lab Framework

### Jak działa tryb Update?

Tryb Update odczytuje statusy i tagi z katalogów `/mapping/` oraz `/scenarios/` i generuje zaktualizowany raport HTML oraz macierz MITRE ATT&CK.

---

### Czy mogę dodać kilka technik do jednej grupy APT?

Tak, możesz wielokrotnie wybierać tę samą grupę, a kolejne techniki zostaną dopisane do tej grupy.

---

### Co zrobić, gdy raport nie pokazuje nowych technik?

Użyj trybu Update lub sprawdź, czy status.csv i tags.json w katalogach zostały poprawnie uzupełnione.

---

### Czy muszę ręcznie poprawiać statusy?

Nie musisz, ale możesz edytować status.csv ręcznie dla masowej edycji i potem odświeżyć raport.

---

### Jak dodać własną technikę?

Najpierw dodaj ją do `enterprise_attack.csv` w katalogu `/tools/`, a potem przejdź proces w kreatorze.

---
