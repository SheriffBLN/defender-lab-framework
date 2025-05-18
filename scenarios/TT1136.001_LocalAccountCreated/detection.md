# Detection for T1136.001 ñ LocalAccountCreated

## Test Details
- Komenda: `net user testuser Pass123! /add`
- Konto zosta≥o utworzone lokalnie przez uøytkownika testowego

## èrÛd≥a LogÛw
- Windows Security Event Log
  - Event ID: **4720** ñ A user account was created
- Microsoft Defender for Endpoint
  - ActionType: **UserAccountCreated**

## Alerty
- Microsoft Defender for Endpoint: ?? Alert wykry≥ stworzenie konta lokalnego
- Dodatkowo wykryto w hunting query (`DeviceEvents` + `UserAccountCreated`)

## Wnioski
- Scenariusz potwierdzony i skutecznie wykryty
- Regu≥a dzia≥a zgodnie z oczekiwaniami
