#  Alert: Wykrycie dodania lub usunięcia konta użytkownika z lokalnej grupy (Add/Remove from Local Group)

##  Opis

Ten alert wykrywa moment, w którym konto użytkownika zostało **dodane** lub **usunięte** z **lokalnej grupy użytkowników** (np. *Administratorzy*), co może oznaczać:

- eskalację uprawnień (np. dodanie konta do grupy Administratorzy),
- próbę ukrycia obecności konta (usunięcie z grupy),
- działania wykonywane przez administratorów bez zgłoszenia,
- aktywność malware lub skryptów persistence.

---

## Techniczne szczegóły

| Źródło                           | Tabela MDE       | Event ID (klasyczny) | ActionType                                       |
|----------------------------------|------------------|-----------------------|--------------------------------------------------|
| Microsoft Defender for Endpoint | `DeviceEvents`   | 4732 / 4733           | `UserAccountAddedToLocalGroup`, `UserAccountRemovedFromLocalGroup` |

---

##  KQL – hunting query

```kql
DeviceEvents
| where ActionType in ("UserAccountAddedToLocalGroup", "UserAccountRemovedFromLocalGroup")
| extend AdditionalFieldsJson = parse_json(AdditionalFields)
| extend
    TargetAccount = AccountName,
    InitiatingUser = InitiatingProcessAccountName,
    InitiatingProcess = InitiatingProcessFileName,
    GroupName = tostring(AdditionalFieldsJson.GroupName),
    GroupDomainName = tostring(AdditionalFieldsJson.GroupDomainName),
    GroupSid = tostring(AdditionalFieldsJson.GroupSid),
    GroupAction = case(
        ActionType == "UserAccountAddedToLocalGroup", "UserAccountAddedToLocalGroup",
        ActionType == "UserAccountRemovedFromLocalGroup", "UserAccountRemovedFromLocalGroup",
        "Inne"
    )
| project
    Timestamp,
    DeviceName,
    GroupAction,
    TargetAccount,
    AccountSid,
    GroupName,
    GroupDomainName,
    GroupSid,
    InitiatingUser
| order by Timestamp desc
