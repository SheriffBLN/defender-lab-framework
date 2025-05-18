#  Alert: Wykrycie modyfikacji lokalnego konta użytkownika (UserAccountModified)

##  Opis

Ten alert wykrywa przypadki **modyfikacji istniejącego lokalnego konta użytkownika** w systemie Windows. Zmiana może dotyczyć np. ustawienia nazwy wyświetlanej, wymuszenia zmiany hasła przy kolejnym logowaniu, czy zmiany flag UAC. Takie działania mogą świadczyć o:

- modyfikacjach dokonywanych przez administratora,
- próbach zakamuflowania konta przez atakującego (np. usunięcie opisu, wyłączenie konta),
- technikach persistence lub lateral movement.

---

## Techniczne szczegóły

| Źródło                           | Tabela MDE       | Event ID (klasyczny) | ActionType              |
|----------------------------------|------------------|-----------------------|--------------------------|
| Microsoft Defender for Endpoint | `DeviceEvents`   | 4738                  | `UserAccountModified`    |

---

##  KQL – hunting query

```kql
DeviceEvents
| where ActionType == "UserAccountModified"
| extend AdditionalFieldsJson = parse_json(AdditionalFields)
| extend
    TargetAccount = AccountName,
    InitiatingUser = InitiatingProcessAccountName,
    InitiatingProcess = InitiatingProcessFileName,
    New_DisplayNameOrComment = tostring(AdditionalFieldsJson.DisplayName),
    PasswordLastSetRawString = tostring(AdditionalFieldsJson.PasswordLastSet),
    PasswordLastSetTime = todatetime(AdditionalFieldsJson.PasswordLastSet),
    New_PrimaryGroupId = tostring(AdditionalFieldsJson.PrimaryGroupId),
    Old_UAC = tostring(AdditionalFieldsJson.UserAccountControlFlags),
    New_UAC = tostring(AdditionalFieldsJson.NewUacValue)
| extend
    NewUAC_Decoded = case(
        New_UAC == "0x10", "Konto bez zaznaczonych opcji (domyślne ustawienia)",
        New_UAC == "0x11", "Konto jest wyłączone",
        New_UAC == "0x210", "Hasło nigdy nie wygasa",
        "Inne / Nieznane ustawienie"
    ),
    MustChangePasswordAtNextLogon = iff(PasswordLastSetRawString == "%%1794", "Tak", "Nie"),
    PasswordChangeDetected = iff(datetime_diff("minute", PasswordLastSetTime, Timestamp) == 120, "Tak", "Nie"),
    WasUACChanged = iff(Old_UAC != New_UAC, "Tak", "Nie")
| project
    Timestamp,
    DeviceName,
    TargetAccount,
    ActionType,
    InitiatingUser,
    InitiatingProcess,
    New_DisplayNameOrComment,
    PasswordLastSetRawString,
    PasswordLastSetTime,
    MustChangePasswordAtNextLogon,
    PasswordChangeDetected,
    New_PrimaryGroupId,
    Old_UAC,
    New_UAC,
    WasUACChanged,
    NewUAC_Decoded
| order by Timestamp desc
