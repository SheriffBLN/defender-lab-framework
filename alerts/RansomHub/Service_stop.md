# Alert: Service Stop

Opis scenariusza, podatności lub techniki.

---

**Technika:** T1489  
**Nazwa:** Service Stop  
**Taktyki:** Impact  
**Status:** Pending  
**Autor:** Krzysztof K.  

---

<!--
Tactics: Impact
Technique ID: T1489
Technique Name: Service Stop
Status: Pending
--> 


---

## Atomic Red Team – dostępne testy dla tej techniki

### Windows - Stop service using Service Controller
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
sc.exe stop #{service_name}
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1489\Windows_-_Stop_service_using_Service_Con/test_1.cmd)

<b>Polecenia cleanup (cmd):</b>
```
sc.exe start #{service_name} >nul 2>&1
```
[Pobierz cleanup_1.cmd](../../scenarios/atomic_tests\T1489\Windows_-_Stop_service_using_Service_Con/cleanup_1.cmd)

### Windows - Stop service using net.exe
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
net.exe stop #{service_name}
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1489\Windows_-_Stop_service_using_net.exe/test_1.cmd)

<b>Polecenia cleanup (cmd):</b>
```
net.exe start #{service_name} >nul 2>&1
```
[Pobierz cleanup_1.cmd](../../scenarios/atomic_tests\T1489\Windows_-_Stop_service_using_net.exe/cleanup_1.cmd)

### Windows - Stop service by killing process
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
taskkill.exe /f /im #{process_name}
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1489\Windows_-_Stop_service_by_killing_proces/test_1.cmd)

[Zobacz testy na GitHubie](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1489)
