# Alert: Safe Mode Boot

Opis scenariusza, podatności lub techniki.

---

**Technika:** T1562.009  
**Nazwa:** Safe Mode Boot  
**Taktyki:** Defense-Evasion  
**Status:** Pending  
**Autor:** Krzysztof K.  

---

<!--
Tactics: Defense-Evasion
Technique ID: T1562.009
Technique Name: Safe Mode Boot
Status: Pending
--> 


---

## Atomic Red Team – dostępne testy dla tej techniki

### Safe Mode Boot
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
bcdedit /set safeboot network
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1562.009\Safe_Mode_Boot/test_1.cmd)

<b>Polecenia cleanup (cmd):</b>
```
bcdedit /deletevalue {current} safeboot
```
[Pobierz cleanup_1.cmd](../../scenarios/atomic_tests\T1562.009\Safe_Mode_Boot/cleanup_1.cmd)

[Zobacz testy na GitHubie](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1562.009)
