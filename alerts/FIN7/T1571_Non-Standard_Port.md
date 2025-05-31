# Alert: Non-Standard Port

**Technique ID:** T1571

**Description:** Adversaries may communicate using a protocol and port pairing that are typically not associated. For example, HTTPS over port 8088(Citation: Symantec Elfin Mar 2019) or port 587(Citation: Fortinet Agent Tesla April 2018) as opposed to the traditional port 443. Adversaries may make changes to the standard port used by a protocol to bypass filtering or muddle analysis/parsing of network data.  Adversaries may also make changes to victim systems to abuse non-standard ports. For example, Registry keys and other configuration settings can be used to modify protocol and port pairings.(Citation: change_rdp_port_conti)

**MITRE Link:** https://attack.mitre.org/techniques/T1571/

Autor: APT Matrix Generator

<!--
Tactics: 
Technique ID: T1571
Status: Pending
-->
