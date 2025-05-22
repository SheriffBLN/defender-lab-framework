# 🏗️ Pipeline – Defender Lab Framework

## Jak działa pipeline?

1. **Wprowadzasz dane** przez kreator w skrypcie (techniki, nazwy, statusy).
2. **Framework generuje:**
   - Pliki markdown (.md) z alertami i scenariuszami
   - Pliki JSON (np. warstwa do MITRE Navigatora)
   - Pliki CSV ze statusami (do masowej edycji)
   - Raporty HTML z macierzą i tabelami
3. **Możesz dowolnie edytować statusy/scenariusze,** po czym użyć trybu Update.
4. **Raporty i mappingi są aktualizowane automatycznie** na podstawie plików źródłowych.

## Struktura katalogów

- **alerts/** — alerty dla każdej techniki/scenariusza (markdown, HTML)
- **scenarios/** — scenariusze testowe i tagi (markdown, JSON)
- **mapping/** — warstwy do Navigatora i statusy (.json, .csv)
- **hunting/** — zapytania KQL, Sigma, YARA itp.
- **report/** — końcowy raport HTML z macierzą MITRE ATT&CK
- **tools/** — kod źródłowy i narzędzia pomocnicze

**FAQ oraz porady znajdziesz w [FAQ.md](FAQ.md).**
