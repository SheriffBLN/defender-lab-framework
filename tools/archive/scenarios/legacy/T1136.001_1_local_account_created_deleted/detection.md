# Detection for T1136.001 – LocalAccountCreated

## Test Details
- Komenda: `net user testuser Pass123! /add`
- Konto zosta³o utworzone lokalnie przez u¿ytkownika testowego

## Log Sources
- Windows Security Event Log
  - Event ID: **4720** – A user account was created
- Microsoft Defender for Endpoint
  - ActionType: **UserAccountCreated**

## Alerty
- Microsoft Defender for Endpoint: ?? Alert wykry³ stworzenie konta lokalnego
- Dodatkowo wykryto w hunting query (`DeviceEvents` + `UserAccountCreated`)

## Wnioski
- Scenariusz potwierdzony i skutecznie wykryty
- Regu³a dzia³a zgodnie z oczekiwaniami
