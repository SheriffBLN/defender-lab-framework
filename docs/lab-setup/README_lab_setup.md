[Read this documentation in English (README_eng.md)](README_eng.md)

# Budowa LAB Microsoft Defender for Endpoint (licencja P2 z O365 Business Basic)

## Wstęp

Chcesz stworzyć własne środowisko do **Advanced Threat Hunting** i **Detection Engineering**? Ten poradnik poprowadzi Cię krok po kroku!

W ramach projektu stworzyłem własny tenant O365 oparty o licencje (Business Basic + Microsoft Defender for Endpoint P2). Oto szczegółowy opis łącznie z napotkanymi problemami i ich rozwiązaniem.

## Spis treści
- [Wstęp](#wstęp)
- [Etap 1: Rejestracja licencji O365 Business Basic](#etap-1-rejestracja-licencji-o365-business-basic)
- [Etap 2: Rejestracja adresu e-mail](#etap-2-rejestracja-adresu-e-mail)
- [Etap 3: Przydzielenie licencji](#etap-3-przydzielenie-licencji)
- [Etap 4: Oczekiwanie na propagację - cierpliwość to klucz](#etap-4-oczekiwanie-na-propagację---cierpliwość-to-klucz)
- [Etap 5: Konfiguracja w Security.microsoft.com](#etap-5-konfiguracja-w-securitymicrosoftcom)
- [Etap 6: Onboarding maszyny Windows 11](#etap-6-onboarding-maszyny-windows-11)
- [Etap 7: Pierwsze alerty i hunting](#etap-7-pierwsze-alerty-i-hunting)
- [Podsumowanie](#podsumowanie)
- [Co dalej?](#co-dalej)

# Etap 1: Rejestracja licencji O365 Business Basic

- ![Licencja Business Basic](screenshots/001_licencja_business_basic.png)

[Rozpocznij darmowy 30-dniowy okres próbny Microsoft 365 Business Basic tutaj](https://www.microsoft.com/en-us/microsoft-365/business/microsoft-365-business-basic)


## Uwaga: Wybór modelu licencyjnego

W trakcie tworzenia labu mamy różne możliwości modelu licencyjnego.

- Najmniej kosztowna opcja: **Microsoft 365 Business Basic** + **Microsoft Defender for Endpoint P2**.
- Licencja **Business Basic** jest dostępna **za darmo przez pierwszy miesiąc** w ramach okresu próbnego.
- Licencja **Defender for Endpoint P2** kosztuje około **30 zł miesięcznie**.

 Po zakończeniu 30-dniowego okresu demo, **całkowity koszt utrzymania labu wynosi około 60 zł miesięcznie** (Business Basic + P2).

### Ciekawostka: Alternatywne możliwości zdobycia licencji

- W przeszłości istniały alternatywne metody pozyskania licencji Defender for Endpoint P2 za darmo na **90 dni**, np. poprzez program **Microsoft 365 Developer Program**.
- Jednak obecnie **trudniej jest zakwalifikować się do programu Developer**, aby otrzymać darmowe licencje E5 (w tym Defendera P2) — Microsoft zaostrzył kryteria przydziału.
- Alternatywnie osoby posiadające aktywne subskrypcje **Visual Studio (MSDN)** nadal mogą mieć dostęp do pełnych licencji E5 w ramach swoich benefitów.

Mimo to **najprostszym i najszybszym sposobem** na zbudowanie labu jest bezpośredni **zakup licencji P2** w modelu miesięcznym i taka też droga została tutaj opisana.

---

- Wybranie wersji "Wypróbuj bezpłatnie przez miesiąc".

Napotkany problem: komunikat o przeciążonych serwerach (wyświetlany w nieskończoność).  
Rejestracja powiodła się dopiero po przejściu do **trybu incognito** w przeglądarce!

- ![Problem przy rejestracji adresu e-mail](screenshots/002_problem_rejestracji_adresu.png)


# Etap 2: Rejestracja adresu e-mail

- ![Rejestracja adresu e-mail](screenshots/003_rejestracja_adresu_email.png)
- ![Szczegóły subskrypcji](screenshots/004_szczegoly_subskrypcji.png)

Po wyborze odpowiedniej licencji Business Basic i przejściu przez wstępne ekrany, system Microsoft poprosi o podanie danych rejestracyjnych dla nowego konta organizacyjnego.

**Typowe kroki rejestracji:**
1. Podanie **adresu e-mail**, który będzie używany do logowania do usług Microsoft 365.
2. Wypełnienie podstawowych informacji o organizacji (nazwa organizacji, kraj, numer telefonu kontaktowego).
3. Wybór **domeny organizacji** (np. `twojefirma.onmicrosoft.com`), którą utworzy dla Ciebie Microsoft.
4. Ustawienie danych logowania: **nazwa użytkownika** oraz **hasło**.
5. Potwierdzenie warunków korzystania z usług.

> **Uwaga:** W moim przypadku proces był szybki, natomiast jeżeli używasz adresu e-mail, który już był kiedyś powiązany z Microsoftem, mogą pojawić się dodatkowe kroki weryfikacyjne.

Po pomyślnej rejestracji, otrzymujesz dostęp do pełnego panelu administratora Microsoft 365, gdzie przypisujesz licencje oraz konfigurujesz kolejne ustawienia potrzebne do budowy labu.

---


# Etap 3: Przydzielenie licencji

Po poprawnym założeniu konta organizacyjnego i przypisaniu podstawowej licencji Business Basic, konieczne było uzyskanie dostępu do licencji **Microsoft Defender for Endpoint P2**.

**Zakup licencji Microsoft Defender for Endpoint P2:**

Jeżeli Twoja organizacja nie ma jeszcze przypisanej licencji Defender P2, możesz ją wyszukać i zakupić manualnie:

1. Przejdź do **Microsoft 365 Admin Center** ➔ **Marketplace**,
2. Wyszukaj frazę **"P2"** w polu wyszukiwania,
3. Znajdź produkt **Microsoft Defender for Endpoint P2** i kliknij **Buy now**.

- ![Marketplace - zakup Defender P2](screenshots/005a_marketplace_zakup_defender_p2.png)

> **Uwaga:** Licencja Defender for Endpoint P2 pojawia się w niektórych przypadkach automatycznie, ale czasami wymaga ręcznego wyszukania. Wyszukanie P2 może być możliwe dopiero po pełnej propagacji danych w organizacji (czasem do kilku godzin od rejestracji).

---

**Przypisanie licencji użytkownikowi:**

Po zakupie licencji P2 należy ją ręcznie przypisać do użytkownika:

1. Wejdź w **Users** ➔ **Active users**,
2. Wybierz użytkownika (Twoje konto),
3. Edytuj licencje ➔ przypisz licencję **Microsoft Defender for Endpoint P2**.

- ![Widok licencji](screenshots/005_widok_licencji.png)
- ![Przypisanie licencji Defender P2](screenshots/006_przypisanie_licencji_defender_p2.png)

Po poprawnym przypisaniu użytkownik będzie widoczny jako właściciel aktywnej licencji umożliwiającej korzystanie z pełnej funkcjonalności Microsoft Defender for Endpoint.



# Etap 4: Oczekiwanie na propagację - cierpliwość to klucz

Po przypisaniu licencji należy odczekać, aż pełna infrastruktura Microsoft Defender for Endpoint zostanie aktywowana w Twoim tenantcie.

**Gdzie sprawdzać status propagacji?**

- Portal administracyjny Microsoft 365 ➔ [https://admin.microsoft.com](https://admin.microsoft.com)
- Portal zabezpieczeń Microsoft Defender ➔ [https://security.microsoft.com](https://security.microsoft.com)

**Kluczowe informacje:**

- W pierwszych godzinach po przypisaniu licencji portal Defender (`security.microsoft.com`) może być niepełny lub niedostępny.
- Typowe komunikaty w tym czasie:
  - "Hang on! We're preparing new spaces for your data and connecting them.",
  - Błędy AxiosError 400 przy próbie przejścia do sekcji takich jak "Advanced Hunting",
  - Brak dostępnych sekcji "Endpoints", "Incidents & Alerts", "Threat Intelligence".

---

**Czas propagacji:**

- W moim przypadku pełna aktywacja trwała około **10-12 godzin**.
- Pierwsze oznaki poprawnego działania pojawiły się po około **1 godzinie** (widoczność zakładek w portalu security), ale nie wszystkie funkcje były wtedy jeszcze dostępne.

---

**Wizualizacja:**

- ![Propagacja po 60 minutach](screenshots/007_propagacja_tenanta_60min.png)
- ![Propagacja do 24h](screenshots/008_oczekiwanie_na_propagacje_24h.png)
- ![Główny dashboard po propagacji](screenshots/009_glowny_dashboard_po_propagacji.png)

---

**Podpowiedź praktyczna:**

- Regularnie odświeżaj portal **security.microsoft.com** – zmiany są stopniowe.
- Jeśli po 24 godzinach nie widzisz zakładek takich jak "Endpoints", "Advanced Hunting", "Incidents & Alerts" – sprawdź poprawność przypisanych licencji lub ponownie zaloguj się do portalu.

---



# Etap 5: Konfiguracja w Security.microsoft.com

- ![Główny dashboard](screenshots/009_glowny_dashboard_po_propagacji.png)

Po kilku godzinach:
- Pełny dostęp do **Endpoints**,
- **Advanced Hunting** działa poprawnie,
- Możliwość onboardowania maszyn.

# Etap 6: Onboarding maszyny Windows 11

Aby móc przeprowadzić testy w środowisku Microsoft Defender for Endpoint, konieczne było przygotowanie osobnej maszyny testowej.  
W moim przypadku środowisko zostało oparte o **Hyper-V** oraz maszynę wirtualną z systemem **Windows 11 Pro**.

---

## Przygotowanie maszyny Windows do labu

Jeżeli nie masz jeszcze obrazu ISO z systemem Windows, możesz skorzystać z oficjalnego narzędzia Microsoft:

- [Pobierz Windows 10 Media Creation Tool](https://www.microsoft.com/software-download/windows10)
- [Pobierz Windows 11 Media Creation Tool](https://www.microsoft.com/software-download/windows11)

> **Rekomendacja:** Pobierz plik ISO i utwórz własną maszynę w Hyper-V lub VirtualBox.  
> Wybierz wersję Windows **Pro**, **Enterprise** lub **Education** — tylko te edycje w pełni wspierają funkcjonalności Defender for Endpoint (m.in. onboarding, EDR, ASR).

---

## Wymagania dla maszyny onboardowanej:

- System operacyjny: Windows 10/11 Pro, Enterprise lub Education.
- Minimalne wymagania sprzętowe:
  - 2 CPU,
  - 4 GB RAM,
  - Dysk 60 GB+ (dla komfortu).
- Maszyna musi mieć:
  - Dostęp do Internetu,
  - Możliwość uruchamiania skryptów `.cmd` (domyślne Execution Policy),
  - Włączoną komunikację wychodzącą na serwisy Microsoft Defender.

---

## Kroki onboardingowe:

1. Wejdź do portalu ➔ [https://security.microsoft.com](https://security.microsoft.com).
2. Przejdź do: **Settings ➔ Endpoints ➔ Device Management ➔ Onboarding**.
3. Wybierz metodę: **Local Script (for up to 10 devices)**.
4. Pobierz wygenerowany pakiet onboardingowy `.zip`.
5. Wypakuj plik i uruchom znajdujący się w nim skrypt `.cmd` jako **Administrator** na maszynie Windows 11.

- ![Pobranie pakietu onboardingowego](screenshots/010_onboarding_pobranie_skryptu.png)

> **Tip:** Skrypt automatycznie połączy urządzenie z usługą Microsoft Defender for Endpoint i zarejestruje je w portalu security.microsoft.com.

---

## Po wykonaniu skryptu:

- Maszyna powinna pojawić się w sekcji ➔ **Devices ➔ Inventory** w portalu security.microsoft.com.
- Status urządzenia powinien wskazywać `Onboarded`.

- ![Widok poprawnie dodanej maszyny](screenshots/012_widok_uruchomionego_onboardingu.png)

---

## Dodatkowa weryfikacja:

Aby upewnić się, że maszyna została poprawnie podłączona:

- Przejdź do ➔ **Devices ➔ Inventory**,
- Wyszukaj swoją maszynę po nazwie (np. `win11-client`),
- Zweryfikuj status: `Onboarding status: Onboarded`.

---

## Praktyczna porada:

Jeśli po 30–60 minutach maszyna nadal nie pojawia się w portalu:
- Upewnij się, że maszyna ma aktywne połączenie z Internetem,
- Sprawdź synchronizację czasu systemowego (błędy czasu mogą blokować komunikację z Defenderem),
- Uruchom ponownie skrypt onboardingowy jako Administrator,
- Opcjonalnie zrestartuj maszynę wirtualną.

---


# Etap 7: Pierwsze alerty i hunting

Po pomyślnym onboardowaniu maszyny do Microsoft Defender for Endpoint, kolejnym krokiem było przeprowadzenie pierwszych testów walidacyjnych.  
Celem było upewnienie się, że:

- Telemetria z maszyny trafia poprawnie do portalu,
- Alerty bezpieczeństwa są generowane i widoczne w konsoli,
- Dane są dostępne w sekcji **Advanced Hunting**.

---

## Wygenerowanie testowego alertu

W celu wywołania kontrolowanego alertu, na onboardowanej maszynie Windows 11 wykonano symulację podejrzanej aktywności:

- Uruchomienie polecenia **PowerShell** zawierającego nietypowe argumenty,
- Wzorzec przypominający potencjalnie złośliwe zachowanie (np. skrypt pobierający plik).

Przykładowa testowa komenda:

```powershell
powershell.exe -NoExit -ExecutionPolicy Bypass -WindowStyle Hidden $ErrorActionPreference= 'silentlycontinue';(New-Object System.Net.WebClient).DownloadFile('http://127.0.0.1/1.exe', 'C:\\test-WDATP-test\\invoice.exe');Start-Process 'C:\\test-WDATP-test\\invoice.exe'
```

# Podsumowanie

| Krok | Czas | Uwagi |
|:---|:---|:---|
| Rejestracja Business Basic | ~30 min (z problemami) | Przejście przez incognito |
| Zakup Defender P2 i przypisanie | ~10 min | Ręczne przypisanie licencji |
| Propagacja w Defender Portal | ~10-12h | Wymagana cierpliwość |
| Onboarding Windows 11 | ~15 min | Skrypt jako Admin |
| Pierwszy alert / hunting | natychmiast | Pełna widoczność |

# Co dalej?

Planowane kolejne kroki:
- Włączenie reguł ASR (Attack Surface Reduction),
- Symulacje BYOVD (wgrywanie podatnych sterowników),
- Budowa własnych custom detection rules.


# Oficjalna dokumentacja i dodatkowe materiały

Jeżeli chcesz zgłębić temat Microsoft Defender for Endpoint i budowy labu, polecam również oficjalne źródła:

- [Microsoft Docs - Microsoft Defender for Endpoint Overview](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-endpoint?view=o365-worldwide)
- [Microsoft Docs - Onboard Devices to Defender for Endpoint](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/onboard-configure?view=o365-worldwide)
- [Microsoft Docs - Advanced Hunting Overview](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-overview?view=o365-worldwide)
- [Microsoft 365 Defender Learning Hub](https://learn.microsoft.com/en-us/training/modules/intro-to-microsoft-365-defender/)

---

**Autor:** Krzysztof Krzymowski  
**Status:** Detection Engineer in Progress

Jeśli doceniasz tę pracę i chcesz wesprzeć rozwój labu, już niedługo uruchamiam **Buy Me a Coffee!**

Stay tuned for future updates and simulations! 
