# 📁 tools/
# Zaktualizowana struktura skryptów z numeracją

# 00a – Wprowadzenie listy technik i danych grupy APT
00a_generate_from_user_input.py
# Wprowadza dane: tryb Single / APT, lista technik, status, autor, nazwa grupy

# 00b – Generacja struktury APT w katalogach alerts/hunting/mapping/scenarios/report
00b_generate_structure_for_apt.py
# Tworzy foldery /APTxx/ w każdej gałęzi (w tym report/)

# 01 – Generacja plików Markdown alertów z szablonu
01_generate_alert_md.py
# Tworzy alerty .md z informacjami MITRE + placeholdery
# ✅ Działa na context["techniques"] jako lista obiektów z "technique_id", "technique_name", "tactics"

# 02 – Wstawienie KQL do alertów z katalogu hunting
02_insert_kql_into_alerts.py
# Wyszukuje pliki .kql i dokleja je do odpowiednich alertów

# 03 – Generacja plików scenariuszy (atak + detekcja)
03_generate_scenarios.py
# Tworzy .md scenariusza z testem dla każdej techniki
# ✅ Teraz iteruje po context["techniques"] i używa tech["technique_id"]

# 04 – Tworzenie warstwy Navigatora
04_generate_mitre_layer.py
# Tworzy APTxx_layer.json na podstawie technik z grupy
# ✅ Korzysta z tech["technique_id"] zamiast surowej listy stringów

# 04a – Generacja pliku status.csv do raportu
04a_generate_status_csv.py
# Skanuje tags.json i tworzy mapping/{APT}/status.csv na podstawie scenariuszy

# 05 – Tworzenie raportu HTML z podsumowaniem i tabelą logiczną + matrix table
05_generate_index_html.py
# Tworzy stylizowany raport HTML dla report/{APT}/index.html na bazie status.csv
# Zawiera tabelę logiczną, kolory, linki do reguł i matrix table

# 06 – Dodanie matrix table (uzupełnienie do raportu)
06_generate_matrix_table.py
# Dodaje html-tabelę z mapping/{APT}/status.csv do index.html
# Wymaga zainstalowanego modułu pandas (pip install pandas)
# Dodaje html-tabelę z mapping/{APT}/status.csv do index.html

# 99 – Skrypt główny do wszystkiego end-to-end
99_merge_all_for_apt.py
# Wykonuje wszystkie powyższe kroki dla podanej grupy APT
