# Alert: Deobfuscate/Decode Files or Information

Opis scenariusza, podatności lub techniki.

---

**Technika:** T1140  
**Nazwa:** Deobfuscate/Decode Files or Information  
**Taktyki:** Defense-Evasion  
**Status:** Pending  
**Autor:** Krzysztof K.  

---

<!--
Tactics: Defense-Evasion
Technique ID: T1140
Technique Name: Deobfuscate/Decode Files or Information
Status: Pending
--> 


---

## Atomic Red Team – dostępne testy dla tej techniki

### Deobfuscate/Decode Files Or Information
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
certutil -encode #{executable} %temp%\T1140_calc.txt
certutil -decode %temp%\T1140_calc.txt %temp%\T1140_calc_decoded.exe
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1140\Deobfuscate_Decode_Files_Or_Information/test_1.cmd)

<b>Polecenia cleanup (cmd):</b>
```
del %temp%\T1140_calc.txt >nul 2>&1
del %temp%\T1140_calc_decoded.exe >nul 2>&1
```
[Pobierz cleanup_1.cmd](../../scenarios/atomic_tests\T1140\Deobfuscate_Decode_Files_Or_Information/cleanup_1.cmd)

### Certutil Rename and Decode
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
copy %windir%\system32\certutil.exe %temp%\tcm.tmp
%temp%\tcm.tmp -encode #{executable} %temp%\T1140_calc2.txt
%temp%\tcm.tmp -decode %temp%\T1140_calc2.txt %temp%\T1140_calc2_decoded.exe
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1140\Certutil_Rename_and_Decode/test_1.cmd)

<b>Polecenia cleanup (cmd):</b>
```
del %temp%\tcm.tmp >nul 2>&1
del %temp%\T1140_calc2.txt >nul 2>&1
del %temp%\T1140_calc2_decoded.exe >nul 2>&1
```
[Pobierz cleanup_1.cmd](../../scenarios/atomic_tests\T1140\Certutil_Rename_and_Decode/cleanup_1.cmd)

[Zobacz testy na GitHubie](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1140)
