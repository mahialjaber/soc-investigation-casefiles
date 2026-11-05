# 🛡️ SOC Investigation Case Files

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-LetsDefend_%7C_Enterprise_SOC-blue)](https://letsdefend.io)
[![Role Focus](https://img.shields.io/badge/Role-Tier--1_SOC_Analyst-059669)](#)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v16.1-red)](https://attack.mitre.org/)

A dedicated repository documenting hands-on Security Operations Center (SOC) alert triage, threat hunting, and incident analysis case files. Every investigation is conducted end-to-end following a defensible 6-step SOC Tier-1 playbook.

---

## 🧭 Investigation Methodology

Every case file in this repository is built using our standardized [Case Template](cases/TEMPLATE.md) to ensure forensic rigor and clear analytical reasoning:

1. **Executive Summary:** A concise 3-sentence operational brief communicating alert trigger, adversary actions, breach status, and immediate containment.
2. **Alert Scope:** Pinpointing affected assets, attacker source IPs, external ASNs, and targeted user/service accounts.
3. **Investigation Timeline (UTC):** Synchronized cross-source telemetry table correlating EDR, SIEM, WAF, firewall, and identity logs chronologically.
4. **What Could Make This Benign? (Disproving the Hypothesis):** Actively testing and documenting alternative benign hypotheses (maintenance windows, authorized vulnerability scanners, standard admin scripts) before escalating.
5. **Extracted IOCs (Defanged):** Defanged IP addresses, malicious domains, URLs, and cryptographic hashes (SHA-256) ready for enrichment and ingestion into threat intelligence feeds.
6. **Containment & Remediation:** Documented tactical containment (EDR network isolation, process termination) and strategic hardening (firewall rules, credential rotation, patching).

---

## 📋 Case File Tracker

*Case files are added incrementally as real investigations are worked and documented.*

| Case # | Alert ID & Description | Category | Verdict | Status | Case File |
| :---: | :--- | :--- | :---: | :---: | :---: |
| 01 | [ET MALWARE MirrorBlast CnC Activity M3 (TA505)](cases/case-01-warzone-1/investigation.md) | Malware / C2 | True Positive | Completed | [Case 01 Report](cases/case-01-warzone-1/investigation.md) |
| — | *Upcoming Case File* | Triage | — | In Progress | [Template](cases/TEMPLATE.md) |

---

## 📁 Repository Structure

```text
soc-investigation-casefiles/
├── README.md                           # Repository overview & triage methodology
├── LICENSE                             # MIT License
└── cases/
    ├── TEMPLATE.md                     # Standardized investigation template
    └── case-01-warzone-1/               # Case 01: MirrorBlast Malware Triage
        ├── investigation.md            # Full defensible investigation case file
        └── screenshots/                # Cropped forensic evidence artifacts
            ├── 01-brim-traffic-analysis.png
            ├── 02-wireshark-http-objects.png
            ├── 03-wireshark-tcp-stream-dropped-files.png
            └── 04-virustotal-threat-intelligence.png
```

---

## 👤 Author

* **Mahi Al Jaber** ([@mahialjaber](https://github.com/mahialjaber))  
* Aspiring SOC Analyst & Detection Engineer | [LinkedIn](https://linkedin.com/in/mahialjaber)
