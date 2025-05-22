class Technique:
    def __init__(self, tid, name="", tactics=None, kql="", cmd="", ps="", status="Pending", author="Unknown"):
        self.tid = tid
        self.name = name
        self.tactics = tactics or []
        self.kql = kql
        self.cmd = cmd
        self.ps = ps
        self.status = status
        self.author = author

    def to_dict(self):
        return {
            "technique_id": self.tid,
            "technique_name": self.name,
            "tactics": ", ".join(self.tactics),
            "kql_queries": self.kql,
            "test_cmd": self.cmd,
            "test_ps": self.ps,
            "triage_tips": "Sprawdź inicjujący proces, użytkownika i źródło logu",
            "status": self.status,
            "author": self.author,
            "detection_table": "| MDE | DeviceEvents | 4720 | UserAccountCreated |"
        }

class APTGroup:
    def __init__(self, name, techniques=None):
        self.name = name
        self.techniques = techniques or []

    def add_technique(self, technique):
        self.techniques.append(technique)

    def generate_summary(self):
        return [tech.to_dict() for tech in self.techniques]