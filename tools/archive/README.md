# 🛡️ Defender Lab Framework

Framework zaprojektowany z myślą o analitykach SOC, threat hunterach i inżynierach detekcji, którzy chcą tworzyć własne **scenariusze testowe** w środowisku Microsoft Defender for Endpoint (MDE). Umożliwia symulowanie ataków, obserwowanie ich w logach oraz mapowanie wyników na techniki **MITRE ATT\&CK**®. Pozwala to sprawdzić, czy zaimplementowane reguły bezpieczeństwa potrafią wykryć dane techniki ataku i gdzie istnieją luki.

> 🔄 Dzięki automatyzacji możesz wygodnie testować skuteczność swoich reguł EDR i generować raporty pokazujące **pokrycie detekcji**.


## 📑 Spis treści

- [🎯 Główne cele](#-główne-cele)
- [⚠️ Wymagania](#️-wymagania-wstępne)
- [🧱 Struktura projektu](#-struktura-projektu)
- [🔁 Pipeline](#-pipeline-automatyzacja)
- [🧪 Tworzenie scenariusza](#-jak-wygląda-scenariusz)
- [🧭 Instrukcja krok po kroku](#-instrukcja-krok-po-kroku)
- [📊 Raporty i mapy](#-stwórz-raport-html)
- [✅ Najlepsze praktyki](#-najlepsze-praktyki-przy-tworzeniu-scenariuszy)
- [🤝 Kontrybucje](#-wkład-w-projekt-i-wsparcie)
- [📄 Licencja](#-licencja)



## 🎯 Główne cele

* 🧪 Tworzenie realistycznych scenariuszy ataku
* 🔍 Walidacja skuteczności reguł detekcji (MDE, Sentinel, Splunk itp.)
* 🧭 Mapowanie technik na **MITRE ATT\&CK** (w tym eksport warstwy do Navigatora)
* 📊 Generowanie interaktywnego raportu HTML z wynikami testów
* ⚙️ Automatyczne zarządzanie statusem testów i przypisanymi regułami

## ⚠️ Wymagania wstępne

* Komputer **Windows 10/11** w środowisku testowym, **onboardowany do Microsoft Defender for Endpoint** (lub konfiguracja labowa – zobacz dokumentację `docs/lab-setup` projektu).
* Zainstalowane **Python 3.x** (do uruchamiania skryptów frameworka).
* **Konto z uprawnieniami administratora** na maszynie testowej (wymagane do symulowania wielu technik ataku).
* Sklonowanie lub pobranie tego repozytorium na maszynę testową (scenariusze będą uruchamiane lokalnie).

**Uwaga:** Uruchamiaj symulacje wyłącznie w odizolowanym środowisku testowym – wykonywane techniki mogą być potencjalnie szkodliwe, nie należy ich używać na systemach produkcyjnych.


## 🧱 Struktura projektu

```
defender-lab-framework/
defender-lab-framework/
├── scenarios/       # Scenariusze testowe (atak, logi, metadata)
├── alerts/          # Definicje alertów (.md z KQL i metadanymi)
├── hunting/         # Wygenerowane zapytania KQL (.kql)
├── mapping/         # Pokrycie technik MITRE ATT&CK + warstwa Navigator
├── tools/           # Skrypty automatyzujące proces testów
├── report/          # Raport HTML z wynikami testów
├── docs/            # dokumentacja i manuale
└── README.md        # Główna instrukcja z linkami do docs/
```

## 🔁 Pipeline (automatyzacja)

Główny skrypt **`tools/merge_all_full.py`** wykonuje cały pipeline automatyzacji, w tym kolejno:

1. **Walidację** struktury plików `tags.json`
2. **Ekstrakcję** zapytań KQL z definicji alertów (`alerts/`) do plików `.kql`
3. **Generowanie statusów** testów wszystkich technik (CSV w folderze `mapping/`)
4. **Eksport** warstwy **ATT\&CK Navigator** (`mapping/mitre-navigator/layer.json`)
5. **Tworzenie raportu HTML** (`report/index.html`) z interaktywnymi wykresami i linkami do szczegółów

Dzięki temu jednym poleceniem można zaktualizować wszystkie wyniki testów i otrzymać gotowy raport i mapę pokrycia ATT\&CK.

## 🧪 Jak wygląda scenariusz?

Każdy scenariusz testowy jest reprezentowany jako oddzielny folder w katalogu `scenarios/`. Przykład struktury plików dla scenariusza **T1136.001\_LocalAccountCreated**:

```
scenarios/T1136.001_LocalAccountCreated/
├── attack.ps1         # Skrypt symulujący technikę (np. wywołujący atak w PowerShell)
├── detection.md       # Opcjonalny opis techniczny detekcji/scenariusza
├── tags.json          # Metadane scenariusza (ID techniki, taktyki, status, powiązany alert)
└── logs/              # Folder na logi z uruchomienia scenariusza (np. output.txt)
```

Minimalna zawartość najważniejszego pliku **`tags.json`** może wyglądać następująco:

```json
{
  "id": "T1136.001",
  "name": "LocalAccountCreated",
  "tactics": ["Persistence", "Privilege Escalation"],
  "status": "Tested",
  "linked_alert": "alerts/identity-management/1_local_account_created_deleted.md"
}
```

**Opis pól w `tags.json`:**

* **id** – identyfikator techniki MITRE ATT\&CK (np. `"T1136.001"`).
* **name** – unikalna nazwa scenariusza (krótko, bez spacji; może nawiązywać do techniki, np. *LocalAccountCreated*).
* **tactics** – lista taktyk ATT\&CK, do których należy dana technika (np. Persistence, Privilege Escalation).
* **status** – status scenariusza. Dostępne wartości:

  * `Pending` – scenariusz zaplanowany, ale **jeszcze nietestowany** (domyślny status początkowy).
  * `Audit` – scenariusz działa w trybie **audit** (np. technika włączona tylko audytowo, bez blokowania – dotyczy np. polityk ASR w trybie Audit).
  * `Tested` – scenariusz został **przetestowany** i potwierdzono wykrycie lub zebrano odpowiednie logi.
* **linked\_alert** – ścieżka do powiązanego pliku alertu (reguły detekcji) w katalogu `alerts/`, który odpowiada danej technice. Dzięki temu pole można powiązać scenariusz z konkretną regułą wykrywającą tę technikę. Jeśli scenariusz nie ma jeszcze przygotowanej reguły detekcji, pole to może pozostać puste lub nieobecne.

> **Nota:** Framework jest **elastyczny co do danych scenariusza** – absolutnym minimum jest plik `tags.json` z wypełnionym **`id`** (technika). Pozostałe elementy (skrypt ataku, alert, opis detekcji) możesz dodawać stopniowo. Dzięki temu możliwe jest zapisanie pomysłu na scenariusz (ze statusem `Pending`) i uzupełnienie brakujących fragmentów w późniejszym czasie, bez przerywania działania frameworka.

## 🧭 Instrukcja krok po kroku

Poniżej opisano, jak utworzyć nowy scenariusz i przejść przez cały proces testowania aż do wygenerowania raportu i warstwy ATT\&CK. Załóżmy, że jako przykład wykorzystamy technikę **T1136.001 – Local Account: Local Account Creation**.

### 0. 🧱 Utwórz nowy scenariusz

Najpierw utwórz szablon scenariusza poleceniem:

```bash
python tools/00b_generate_scenario.py --id T1136.001 --name LocalAccountCreated
```

Polecenie to wygeneruje nowy folder w `scenarios/` o nazwie `T1136.001_LocalAccountCreated`, zawierający podstawowe pliki: `attack.ps1`, `detection.md`, `tags.json` (wypełniony domyślnymi wartościami) oraz pusty folder `logs/`. Teraz możesz zacząć uzupełniać ten scenariusz treścią.

💡 **Alternatywna metoda:** Jeśli posiadasz już wcześniej przygotowane definicje reguł alertów (plików `.md` w folderze `alerts/`) dla testowanych technik, możesz **automatycznie wygenerować scenariusze** na ich podstawie. Wystarczy uruchomić:

```bash
python tools/00a_generate_from_alerts.py
```

Skrypt 00a przeiteruje przez wszystkie pliki `.md` w katalogu `alerts/` i dla każdego, który zawiera wymagane metadane, utworzy odpowiadający mu katalog w `scenarios/` (o ile taki scenariusz jeszcze nie istnieje). Pliki `tags.json` zostaną uzupełnione danymi z definicji alertu – m.in. **ID techniki**, **nazwą techniki**, listą **taktyk** oraz ścieżką **linked\_alert** wskazującą na dany plik. Upewnij się, że w plikach alertów umieściłeś w komentarzu wymagane pola (jak **Tactics**, **Technique ID**, **Technique Name**, **Status** – zgodnie z przykładem w repozytorium), aby skrypt mógł je odczytać. Ta metoda pozwala szybko zainicjować wiele scenariuszy jednocześnie, jeśli masz już bazę reguł detekcji dla technik.

### 1. 🔔 Stwórz plik alertu

Następnie utwórz plik z definicją **alertu/detekcji** powiązanego z tą techniką. Plik powinien mieć format Markdown (`.md`) i być umieszczony w odpowiedniej podkategorii katalogu `alerts/`. Przykładowo dla techniki tożsamości (Identity Management):

```
alerts/identity-management/1_local_account_created_deleted.md
```

W utworzonym pliku alertu dodaj zapytanie **KQL** odpowiadające wykrywaniu danej techniki. Umieść je w bloku kodowym Markdown, np.:

````markdown
```kql
DeviceEvents
| where ActionType == "UserAccountCreated"
````

````

Możesz również w tym pliku opisać szczegóły alertu (cele, źródła danych, itd.), a wymagane meta-informacje o technice (taktyki, ID, nazwę, status) dodaj w komentarzu HTML – zobacz istniejące przykłady plików w folderze `alerts/`. Informacje te posłużą automatycznym skryptom do skojarzenia alertu ze scenariuszem.

### 2. 📥 Wyciągnij KQL z alertów

Teraz, gdy masz przygotowany plik alertu z zapytaniem, użyj skryptu do wyodrębnienia wszystkich zapytań KQL do osobnych plików:

```bash
python tools/01_extract_kql_from_alerts.py
````

Skrypt 01 automatycznie utworzy pliki `.kql` w katalogu `hunting/` na podstawie zapytań zawartych w plikach alertów (`alerts/`). Każdy znaleziony blok kodu KQL zostanie zapisany jako oddzielny plik `.kql` (ścieżki i nazwy plików odpowiadają strukturze katalogu alertów). Dzięki temu łatwo podejrzysz lub wykorzystasz zebrane zapytania detekcyjne (np. do uruchomienia ich w portalu logów).

### 3. ✅ Sprawdź poprawność tagów

Przed uruchomieniem testu, warto upewnić się, że metadane scenariuszy są poprawne. Wykonaj walidację plików `tags.json` za pomocą:

```bash
python tools/02_validate_tags.py
```

Skrypt 02 sprawdzi każdy plik `tags.json` w katalogu `scenarios/` pod kątem wymaganych pól (`id`, `name`, `tactics`, `status`, `linked_alert` itp.) oraz poprawności ich formatów. Jeśli jakiegoś pola brakuje lub zawiera błędną wartość, zostanie to wypisane na konsoli. Taka walidacja pomaga wychwycić ewentualne literówki (np. niepoprawny identyfikator techniki) jeszcze przed uruchomieniem symulacji.

### 4. ⚙️ Uruchom scenariusz na maszynie testowej

🛑 **Uwaga:** Ten krok wykonaj **wyłącznie na maszynie testowej** (np. Windows 11 z włączonym MDE). Symulacja ataku może modyfikować system – zadbaj, by było to kontrolowane środowisko labowe!

Aby uruchomić przygotowany scenariusz, skorzystaj ze skryptu:

```bash
python tools/03_run_scenario.py --id T1136.001
```

Spowoduje to odszukanie scenariusza o podanym ID techniki (u nas T1136.001) i uruchomienie znajdującego się w nim skryptu `attack.ps1` w powłoce PowerShell (z ominięciem polityki wykonania). Efekty działania techniki zostaną zapisane do pliku `logs/output.txt` wewnątrz katalogu scenariusza. Po wykonaniu tego kroku w folderze `scenarios/T1136.001_LocalAccountCreated/logs/` powinien pojawić się plik `output.txt` z wynikami działania symulacji (np. komunikatami z PowerShell lub potwierdzeniem wykonania czynności).

### 5. 📌 Wygeneruj statusy testów

Po przeprowadzeniu testu (lub serii testów), możesz zaktualizować zbiorcze zestawienie statusów wszystkich scenariuszy:

```bash
python tools/04_generate_status.py
```

Skrypt 04 przechodzi przez wszystkie foldery w `scenarios/` i na podstawie każdego `tags.json` generuje w katalogu `mapping/` plik `status.csv`. W pliku CSV znajdziesz listę wszystkich technik wraz z nazwami scenariuszy, przypisanymi taktykami, bieżącym statusem (`Pending`, `Audit` lub `Tested`) oraz powiązanym alertem (jeśli podano). Tabela ta ułatwia śledzenie pokrycia – np. możesz otworzyć `mapping/status.csv` w arkuszu kalkulacyjnym, by szybko sprawdzić, które techniki są już przetestowane, a które jeszcze czekają.

### 6. 📊 Stwórz raport HTML

Teraz wygeneruj **raport HTML** podsumowujący pokrycie technik przez Twoje scenariusze:

```bash
python tools/05_generate_report.py
```

Skrypt 05 wygeneruje pliki raportu w folderze `report/` (w szczególności `report/index.html`). Raport zawiera m.in.:

* interaktywny **wykres** kołowy pokazujący procent pokrytych technik ATT\&CK (wg statusów),
* **tabelę** ze wszystkimi scenariuszami, technikami i linkami do szczegółów (m.in. do odpowiednich plików alertów oraz zapytań huntingowych `.kql`).

Otwórz `report/index.html` w przeglądarce, aby przejrzeć wyniki. Możesz to zrobić lokalnie (plik HTML nie wymaga serwera). Jeżeli chcesz podzielić się wynikami z zespołem lub przełożonym, rozważ opublikowanie zawartości folderu `report/` poprzez GitHub Pages – dzięki temu raport będzie dostępny online (i aktualizowany po każdych testach).

### 7. 🧭 Eksportuj warstwę do MITRE Navigator

Ostatnim krokiem (opcjonalnym) jest wygenerowanie pliku z **warstwą ATT\&CK Navigator**, który pozwoli zobrazować pokrycie technik na mapie MITRE:

```bash
python tools/06_generate_navigator_json.py
```

Skrypt 06 utworzy plik warstwy (np. `mapping/mitre-navigator/layer.json`) zgodny z formatem **ATT\&CK Navigator**. Możesz załadować ten plik na stronie [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/) (opcją *Upload*), co umożliwi interaktywne przeglądanie, które techniki są pokryte (oznaczone) przez Twoje scenariusze, a które nie.

## 🔄 Alternatywnie: wszystko naraz

W powyższych krokach każdy etap (ekstrakcja KQL, walidacja, raporty itd.) wywoływaliśmy osobno, co daje kontrolę nad procesem. Jeśli jednak chcesz **zaoszczędzić czas** lub zautomatyzować całość, możesz uruchomić cały pipeline jednym poleceniem:

```bash
python tools/merge_all_full.py
```

Skrypt **`merge_all_full.py`** wykona automatycznie wszystkie kroki 2–7 opisane powyżej (poza uruchomieniem `attack.ps1` na maszynie testowej). W praktyce, po przygotowaniu scenariuszy i ewentualnym odpaleniu ataków, uruchomienie *merge\_all* spowoduje od razu wygenerowanie zaktualizowanych statusów, raportu HTML oraz pliku warstwy dla Navigatora – wszystko w jednym przebiegu.

## 🧪 Przykład pełnego przepływu

Poniżej krótki przykład ilustrujący cały proces tworzenia i testowania scenariusza od zera:

1. **Tworzysz nowy scenariusz** o technice `T1547.001_RunKey` (Persistence: Run Registry Key).
2. **W pliku** `attack.ps1` **dodajesz** komendy PowerShell, które modyfikują odpowiednie klucze rejestru (symulacja utworzenia wartości RunKey dla utrwalenia).
3. **Piszesz regułę detekcji** w pliku `.md` (np. `alerts/persistence/...`) i dodajesz w nim odpowiednie zapytanie KQL, które wykrywa tworzenie wartości w RunKey.
4. **Używasz** `merge_all_full.py`, **żeby zebrać wszystko** w jeden raport (skrypt automatycznie wyciąga KQL, generuje statusy, raport HTML i warstwę Navigatora).
5. **Otwierasz ATT\&CK Navigator** i widzisz, że technika `T1547.001` jest podświetlona jako pokryta w Twojej warstwie – scenariusz został pomyślnie dodany i przetestowany! ✅

*(W powyższym przykładzie zakładamy, że po napisaniu `attack.ps1` uruchomiłeś go na swoim labie Windows, co wygenerowało zdarzenia w logach – reguła KQL mogła je wykryć, dlatego oznaczono technikę jako **Tested**.)*

## 🚀 Jak tworzyć i rozwijać scenariusze

Tworzenie dobrego scenariusza testowego to proces, który można podzielić na kilka etapów. Poniżej znajdziesz zalecany **workflow** wraz z wskazówkami i dobrymi praktykami:

**Krok 1: Wybór techniki i celu scenariusza.** Na początku określ, **jaką technikę ataku chcesz zasymulować** i **co chcesz sprawdzić**. Najlepiej wybierać techniki z katalogu MITRE ATT\&CK, które są istotne dla Twojego środowiska lub które odpowiadają ostatnio obserwowanym zagrożeniom. Przykład: technika *Create Account: Local Account* (T1136.001) – chcemy sprawdzić, czy nasza organizacja wykryje utworzenie nietypowego konta lokalnego.

**Krok 2: Utworzenie scenariusza w frameworku.** Gdy masz wybraną technikę, wygeneruj dla niej **szablon scenariusza** w folderze `scenarios/`. Możesz skorzystać ze skryptu (jak pokazano w kroku 0 powyżej) lub skopiować istniejący scenariusz jako bazę. W pliku `tags.json` uzupełnij podstawowe informacje: identyfikator techniki (`id`), nazwę scenariusza (`name`) oraz przypisz właściwe taktyki ATT\&CK (`tactics`). Na tym etapie pole `status` może pozostać `"Pending"` – dopóki nie przeprowadzisz testu – a pole `linked_alert` możesz wypełnić, jeśli od razu masz gotową regułę, lub zostawić na później.

**Krok 3: Przygotowanie symulacji ataku.** W pliku `attack.ps1` zaimplementuj **akcje, które wywołują daną technikę**. Postaraj się, aby scenariusz był **realistyczny** – używaj narzędzi i metod zbliżonych do tych, które potencjalnie zastosuje atakujący. Np. dla techniki tworzenia konta lokalnego możesz użyć polecenia `net user` lub odpowiednich cmdletów PowerShell do utworzenia i usunięcia użytkownika. Upewnij się, że skrypt nie wyrządzi trwałej szkody Twojemu labowi (np. jeśli tworzysz konto, usuń je w ramach czyszczenia). Pamiętaj, że nie musisz od razu dopracowywać skryptu do perfekcji – celem jest wygenerowanie **logów** bezpieczeństwa, które będzie można wykryć.

**Krok 4: Określenie oczekiwanej detekcji.** Równolegle (lub po przygotowaniu ataku) zadbaj o **logikę detekcji**, która powinna złapać dany atak. Jeśli organizacja posiada już wdrożoną regułę (np. w Microsoft 365 Defender lub Sentinel), spróbuj zdobyć jej definicję (zapytanie KQL, Reguła analizy itp.). Jeśli nie, możesz samodzielnie przygotować prostą regułę wyszukującą w logach charakterystyczne zdarzenie. Taką definicję zapisz w nowym pliku alertu `.md` w folderze `alerts/` – wraz z krótkim opisem i zapytaniem KQL w bloku kodu. W pliku `tags.json` Twojego scenariusza ustaw pole `linked_alert` tak, aby wskazywało na ten plik (dzięki temu raport połączy scenariusz z regułą).

**Krok 5: Testowanie scenariusza.** Gdy **atak i detekcja są gotowe**, przeprowadź test w kontrolowanym środowisku. Uruchom skrypt `attack.ps1` **na maszynie testowej** (np. używając `03_run_scenario.py`, jak opisano wcześniej). Monitoruj, czy akcje zostały wykonane pomyślnie i czy pojawiły się oczekiwane zdarzenia w logach (np. w dzienniku zdarzeń Windows, w portalu Defender/Sentinel lub w pliku `output.txt` zebranym przez skrypt). Ten etap może wymagać iteracji – jeśli atak się nie powiódł lub logi się nie pojawiły, popraw skrypt i spróbuj ponownie. **Wskazówka:** Czasem pomocne jest ręczne wykonanie komend z `attack.ps1` krok po kroku, obserwując na bieżąco generowane zdarzenia.

**Krok 6: Weryfikacja wykrycia.** Sprawdź, czy Twoja reguła detekcji zadziałała. Jeśli korzystasz z Microsoft Defender/Sentinel, zobacz czy wygenerowany został alert lub zdarzenie odpowiadające technice. Jeśli pisałeś własne zapytanie KQL, uruchom je na zebranych logach (np. zaimportuj plik `.kql` do zakładki Hunting w Sentinel). **Jeśli detekcja się powiodła**, możesz uznać scenariusz za udany – zaktualizuj w `tags.json` pole `status` na `"Tested"`. Warto również uzupełnić plik `detection.md` o notatki: np. jakie zdarzenia zostały zarejestrowane, ID alertu w Defenderze, ewentualne zrzuty ekranu czy dodatkowe wnioski. **Jeśli detekcja się nie powiodła**, nie zrażaj się – oznacza to, że masz wartościową informację o luce. Pozostaw status `Pending` i zastanów się, co poprawić: czy potrzeba dopisać lub dostroić regułę detekcji? a może zmodyfikować scenariusz ataku, by bardziej przypominał realne zagrożenie? Wprowadź zmiany i powtórz test.

**Krok 7: Utrzymanie i dalszy rozwój.** Dodawanie jednego scenariusza to początek. Framework pozwala Ci w ten sam sposób rozwijać **kolejne scenariusze** dla różnych technik – dzięki spójnej strukturze możesz z czasem zbudować całą bibliotekę testów. Pamiętaj, by **regularnie generować raport** (skryptem 05 lub `merge_all_full.py`), by mieć aktualny obraz pokrycia ATT\&CK. Analizuj wygenerowaną warstwę Navigatora – wskazówki w niej zawarte pomogą Ci zdecydować, które obszary (techniki/taktyki) warto pokryć następnymi scenariuszami. Gdy techniki czy reguły ulegają zmianie (np. pojawi się lepsza metoda detekcji), wróć do istniejących scenariuszy i **aktualizuj je**. Framework ułatwi Ci śledzenie postępów dzięki polom statusów i automatycznym raportom.

### Najlepsze praktyki przy tworzeniu scenariuszy

* **Realizm przede wszystkim:** Twórz scenariusze odzwierciedlające prawdziwe techniki ataków, najlepiej takie, które były obserwowane lub są istotne dla Twojej organizacji. Np. techniki z kategorii Persistence czy Defense Evasion dostarczają wartościowych testów.
* **Powiąż z regułami wykrycia:** Staraj się, aby każdy scenariusz był **zmapowany do co najmniej jednej reguły detekcji** (wpisz odpowiedni plik w `linked_alert`). Scenariusz bez żadnej reguły referencyjnej też jest przydatny (bo pokazuje lukę), ale ostatecznym celem jest, by każda symulowana technika miała jakąś detekcję.
* **Iteracyjne uzupełnianie:** Nie musisz od razu tworzyć perfekcyjnego scenariusza ze wszystkimi danymi. Zostaw sobie możliwość pracy iteracyjnej – dodaj nowy scenariusz ze statusem `Pending`, jeśli masz pomysł, ale brakuje Ci czasu na pełne przetestowanie. Wrócisz do niego, gdy będziesz gotów. Framework i tak uwzględni go w raporcie (oznaczając jako nieprzetestowany).
* **Stosuj prawidłowe ID technik:** W plikach `tags.json` zawsze używaj poprawnych identyfikatorów ATT\&CK (np. `"T1547.001"` zamiast customowych nazw). Tylko wtedy narzędzia jak Navigator prawidłowo zmapują Twoje wyniki. Jeśli technika nie ma numeru podtechniki, użyj formatu `"TXXXX"` (np. T1547).
* **Testuj bezpiecznie:** Każdy atak uruchamiaj **tylko w odizolowanym labie**. Upewnij się, że masz zgodę na testy bezpieczeństwa w danym środowisku. Nigdy nie wykonuj tych scenariuszy w środowisku produkcyjnym lub na maszynie z wrażliwymi danymi.
* **Dokumentuj co ważne:** Wykorzystaj `detection.md` do zanotowania istotnych spostrzeżeń z testu. Ta dokumentacja posłuży Tobie i innym – np. można tam opisać, które logi były kluczowe, jakie ID alertów wygenerowano, czy potrzebne były dodatkowe zmiany w konfiguracji.
* **Dzielenie się wynikami:** Rozważ publikowanie raportu HTML (np. za pomocą GitHub Pages) lub eksportowanych warstw ATT\&CK w ramach zespołu. Mogą one służyć jako **dokumentacja stanu bezpieczeństwa** – pokazują, które techniki macie pokryte detekcją, a gdzie są braki. Taki raport może stać się częścią cyklicznych przeglądów bezpieczeństwa lub portfolio zespołu.

## 🤝 Wkład w projekt i wsparcie

Masz pomysł na nowy scenariusz albo znalazłeś błąd? Świetnie – **zapraszamy do kontrybucji!** Oto jak możesz dodać swój wkład do Defender Lab Framework:

1. **Sforkuj to repozytorium** na GitHub, aby mieć własną kopię projektu.
2. **Utwórz nowy scenariusz** w katalogu `scenarios/` (np. przy użyciu skryptu `00b_generate_scenario.py` dla właściwego ID techniki). Dodaj wszystkie potrzebne pliki: wypełnij `tags.json` (w szczególności upewnij się, że `id` to poprawny identyfikator ATT\&CK, a `status` ustaw na `Pending` jeśli nie masz pewności co do detekcji), zaimplementuj logikę ataku w `attack.ps1`, dołącz plik alertu z KQL w `alerts/` (i zaktualizuj pole `linked_alert`), oraz ewentualnie dodaj opis w `detection.md`.
3. **Przetestuj swój scenariusz** lokalnie – upewnij się, że skrypt działa, a wygenerowane przez niego logi są zgodne z oczekiwaniami. Zaktualizuj status na `Tested` jeśli udało Ci się uzyskać wykrycie.
4. **Wyślij Pull Request (PR)** z wprowadzonymi zmianami do głównego repozytorium. Opisz krótko, co dodaje Twój scenariusz (jaka technika, jaki typ ataku, jaka reguła detekcji).

Po zgłoszeniu PR, zostanie on przejrzany przez opiekuna projektu – chętnie go sprawdzę, przetestuję i po dyskusji połączę z główną gałęzią 🙌. W ten sposób Twój scenariusz może pomóc innym!

Masz pytania lub uwagi? Najszybciej będzie otworzyć **issue** na GitHub (do zgłoszenia problemu lub pomysłu). Możesz też śmiało napisać do mnie na **LinkedIn** – jestem otwarty na feedback i dyskusje 💬.

Jeśli uważasz, że ten framework jest przydatny i chcesz okazać wsparcie, rozważ drobny gest: **[postaw mi kawę ☕](https://buymeacoffee.com/yourlink)** – z góry dziękuję! 🙏

## 📄 Licencja

Projekt dostępny jest na licencji **MIT**. Możesz z niego swobodnie korzystać, rozwijać go i dzielić się nim (forkować, modyfikować) zgodnie z warunkami licencji MIT. Szanuj jednak wkład innych – zachowaj informację o autorach projektu. Powodzenia w budowaniu własnego labu do testów obrony! ❤️📖
