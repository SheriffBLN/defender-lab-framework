# MITRE ATT&CK Navigator Mapping (TTP)

## Plik: `lab-detection-mapping-COMBINED.json`

Ta warstwa zawiera jednoczesne przypisanie technik głównych oraz ich podtechnik. Ułatwia to analizę w Navigatorze i zapewnia pełną widoczność.

---

## 🎨 Legenda kolorów:

- 🟩 `#66ff66` – Reguła przetestowana i wykrywana (Tested in lab)
- 🟨 `#ffff66` – Reguła ASR uruchomiona w trybie audit, ale jeszcze nieprzetestowana (Audit only)

---

## ✅ Objęte reguły (przetestowane):

| Technika ATT&CK | ID | Taktyka ATT&CK | Status | Reguła |
|------------------|----|----------------|--------|--------|
| Windows Management Instrumentation Subscription | T1546.003 | Persistence | Tested in lab | ASR-WMI-Test.md |
| Create Account | T1136 | Persistence | Tested in lab | Parent of T1136.001 |
| Local Account | T1136.001 | Persistence | Tested in lab | 1_local_account_created_deleted.md |
| Account Manipulation | T1098 | Privilege Escalation, Defense Evasion | Tested in lab | 1_local_account_created_deleted.md, 2_UserAccountAddedToLocalGroup_RemovedFromLocalGroup.md, 3_LocalUserAccountModified.md |
| Valid Accounts | T1078 | Persistence, Defense Evasion | Tested in lab | 1_local_account_created_deleted.md, 2_UserAccountAddedToLocalGroup_RemovedFromLocalGroup.md |
| Account Access Removal | T1531 | Defense Evasion, Impact | Tested in lab | 1_local_account_created_deleted.md |

---

## 🟨 Reguły ASR w trybie audit:

| Technika ATT&CK | ID | Taktyka ATT&CK | Status | Reguła |
|------------------|----|----------------|--------|--------|
| Exploitation for Privilege Escalation | T1068 | Privilege Escalation | Audit only | ASR |
| Credential Dumping | T1003 | Credential Access | Audit only | Parent of T1003.001 |
| LSASS Memory | T1003.001 | Credential Access | Audit only | ASR |
| User Execution | T1204 | Execution | Audit only | Parent of T1204.002 |
| Malicious File | T1204.002 | Execution | Audit only | ASR |
| Cmd & Script Interpreter | T1059 | Execution | Audit only | Parent of T1059.001, T1059.005 |
| Office Child Processes / Macros | T1059.005 | Execution | Audit only | ASR |
| Office Communication Apps | T1059.001 | Execution | Audit only | ASR |
| Process Injection | T1055.001 | Defense Evasion | Audit only | ASR |
| Obfuscated Scripts | T1027 | Defense Evasion | Audit only | ASR |
| Ransomware Protection | T1486 | Impact | Audit only | ASR |
| SMB Credential Stealing | T1555.003 | Credential Access | Audit only | ASR |

---

##  Jak zaimportować:

1. Wejdź na [MITRE Navigator](https://mitre-attack.github.io/attack-navigator/)
2. Kliknij: **Open Existing Layer**
3. Wybierz plik `lab-detection-mapping-COMBINED.json`
4. Gotowe!

---

##  Uwagi

- Ta wersja mapy zawiera zarówno **techniki główne**, jak i **podtechniki**, aby ułatwić analizę i prezentację.
- Poprawiono klasyfikację modyfikacji konta lokalnego (T1098 zamiast T1087.001).
