[Przeczytaj to FAQ po polsku (FAQ.md)](FAQ.md)

# ❓ FAQ – Defender Lab Framework

### How does Update mode work?

Update mode reads statuses and tags from `/mapping/` and `/scenarios/` directories and generates an updated HTML report and MITRE ATT&CK matrix.

---

### Can I add several techniques to one APT group?

Yes, you can choose the same group multiple times and subsequent techniques will be assigned to it.

---

### What if the report doesn't show new techniques?

Use Update mode or check that `status.csv` and `tags.json` in the directories have been filled in correctly.

---

### Do I need to edit statuses manually?

You don't have to, but you can edit `status.csv` manually for bulk changes and then refresh the report.

---

### How do I add my own technique?

First add it to `enterprise_attack.csv` in the `/tools/` directory and then go through the wizard process.

---
