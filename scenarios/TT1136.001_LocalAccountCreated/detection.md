# Detection for T1136.001 � LocalAccountCreated

## Test Details
- Komenda: `net user testuser Pass123! /add`
- Konto zosta�o utworzone lokalnie przez u�ytkownika testowego

## �r�d�a Log�w
- Windows Security Event Log
  - Event ID: **4720** � A user account was created
- Microsoft Defender for Endpoint
  - ActionType: **UserAccountCreated**

## Alerty
- Microsoft Defender for Endpoint: ?? Alert wykry� stworzenie konta lokalnego
- Dodatkowo wykryto w hunting query (`DeviceEvents` + `UserAccountCreated`)

## Wnioski
- Scenariusz potwierdzony i skutecznie wykryty
- Regu�a dzia�a zgodnie z oczekiwaniami
