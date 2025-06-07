[Przeczytaj ten dokument po polsku (Pipeline.md)](Pipeline.md)

# 🏗️ Pipeline – Defender Lab Framework

## How does the pipeline work?

1. **You provide data** through the script wizard (techniques, names, statuses).
2. **The framework generates:**
   - Markdown (.md) files with alerts and scenarios
   - JSON files (for example layers for the MITRE Navigator)
   - CSV files with statuses (for bulk editing)
   - HTML reports with the matrix and tables
3. **You can freely edit statuses/scenarios,** then use the Update mode.
4. **Reports and mappings are updated automatically** based on the source files.

## Directory structure

- **alerts/** — alerts for each technique/scenario (markdown, HTML)
- **scenarios/** — test scenarios and tags (markdown, JSON)
- **mapping/** — Navigator layers and statuses (.json, .csv)
- **hunting/** — KQL, Sigma, YARA queries etc.
- **report/** — final HTML report with the MITRE ATT&CK matrix
- **tools/** — source code and helper tools

**Find FAQ and tips in [FAQ.md](FAQ.md).**
