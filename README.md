# 🛡️ SOC Investigation Case Files

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Focus](https://img.shields.io/badge/Focus-Real--World_%26_Homelab_SOC-blue)](#)
[![Role](https://img.shields.io/badge/Role-Tier--1_SOC_Analyst-059669)](#)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v16.1-red)](https://attack.mitre.org/)

Hands-on Security Operations Center (SOC) alert triage, threat hunting, and incident analysis case files. Each investigation documents real-world and lab threat scenarios end-to-end following a defensible 6-step SOC Tier-1 framework.

---

## 🧭 Investigation Methodology

Every case file follows a standardized triage workflow:

1. **Executive Summary:** Rapid 3-sentence operational brief (trigger, impact, containment).
2. **Alert Scope:** Targeted assets, attacker IPs, external ASNs, and compromised identities.
3. **Investigation Timeline:** Correlated cross-source telemetry (Brim, Wireshark, SIEM, EDR) with visual forensic evidence.
4. **Disproving the Benign Hypothesis:** Verifying change windows, vulnerability scanners, or admin scripts before declaring a true positive.
5. **Defanged IOCs:** Clean IPv4s, domains, hashes, and dropped file paths ready for CTI ingestion.
6. **Containment & Remediation:** Tactical endpoint isolation, network blocking, and Tier-2 escalation.

---

## 📋 Case Files

| Case # | Alert & Scenario | Focus | Verdict | Report |
| :---: | :--- | :--- | :---: | :---: |
| **01** | [ET MALWARE MirrorBlast CnC Activity M3 (TA505)](cases/case-01-warzone-1/investigation.md) | PCAP / C2 Triage | **True Positive** | [Read Case File](cases/case-01-warzone-1/investigation.md) |
| **02** | [Persistence & Lateral Execution via WMIC & PowerShell](cases/case-02-investigating-with-splunk/investigation.md) | SIEM / Splunk | **True Positive** | [Read Case File](cases/case-02-investigating-with-splunk/investigation.md) |
| **03** | [Phishing Unfolding – DNS Exfiltration via PowerShell & nslookup](cases/case-03-phishing-unfolding/investigation.md) | SOC Sim / Splunk / Sysmon | **True Positive** | [Read Case File](cases/case-03-phishing-unfolding/investigation.md) |
| **04** | [End-to-End Enterprise Intrusion – Macro Foothold to Exfiltration](cases/case-04-macro-foothold-to-exfiltration/investigation.md) | SOC Sim / Sysmon / C2 | **True Positive** | [Read Case File](cases/case-04-macro-foothold-to-exfiltration/investigation.md) |
| **05** | *Upcoming Investigation* | Host / Network | In Progress | Pending |

---

## 👤 Author

* **Mahi Al Jaber** ([@mahialjaber](https://github.com/mahialjaber))  
* Security Analyst / Detection Engineer | [X (@mahialjaber)](https://x.com/mahialjaber)
