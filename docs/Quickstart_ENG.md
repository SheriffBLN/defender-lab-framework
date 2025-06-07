[Przeczytaj ten poradnik po polsku (Quickstart.md)](Quickstart.md)

# ⚡ Quickstart – Defender Lab Framework

Want to get started quickly? Follow this step-by-step guide:

**Run the main script**
```powershell
python.exe .\tools\main.py
```

**Select the work mode:**
- **SingleTechnique** – individual techniques combined into a single matrix
- **APT Group** – create a separate matrix for an APT group
- **Update** – mass update based on status.csv
- **APT Matrix from STIX** – generate a matrix from a STIX file (`mapping/<APT>`, `report/<APT>`)
- **Global Coverage** – create a matrix from the last 30 days in `mapping/global_coverage` and `report/global_coverage`
- **AlertEvidence Matrix** – build reports from `tools/helpers/AlertEvidence.csv` in the `alert_evidence_reports` directory
- **Full Navigator Export** – create a `layer.json` file in each `mapping/*`

**Follow the wizard:**
The framework will walk you through the process (adding techniques, names, statuses, etc.)

**Open the generated reports:**
- HTML reports are located in `/report/`
- Matrices and mappings in `/mapping/`
- Alerts in `/alerts/`
- Scenarios in `/scenarios/`
