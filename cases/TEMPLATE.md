# Case [XX]: [Alert ID - Alert Title / Description]

- **Alert ID / Rule:** [e.g., SOC165 / Rule Name]
- **Severity:** [Low / Medium / High / Critical] | **Triage Verdict:** [True Positive / False Positive]
- **Escalation Decision:** [Escalated to Tier 2 / Closed - Benign / Host Contained]
- **MITRE ATT&CK:** [e.g., T1190 - Exploit Public-Facing Application]

---

## 1. Executive Summary (3 sentences max)
*State clearly what rule fired, what behavior was observed, whether the adversary succeeded or failed, and what tactical containment action was executed.*

---

## 2. Alert Scope
- **Affected Host / IP:** `[Hostname]` (`[IP Address]`)
- **Source / Attacker IP:** `[Attacker IP]` (`[ASN / Geo / Ownership]`)
- **Compromised Identity:** `[Username / Service Account]`

---

## 3. Investigation Timeline (UTC)
| Timestamp (UTC) | Log Source | Event / Finding |
| :--- | :--- | :--- |
| `YYYY-MM-DD HH:MM:SS` | [e.g., WAF / EDR / Syslog] | [Detailed finding or command line observed] |

---

## 4. What Could Make This Benign? (Disproving the Hypothesis)
*Before declaring a true positive, systematically test and document benign explanations: authorized penetration testing, vulnerability scanning, system administration baselines, scheduled maintenance windows, or developer testing.*

---

## 5. Extracted IOCs (Defanged)
- **IPv4:** `xxx.xxx.xxx[.]xxx`
- **Domain / URL:** `hxxps://example[.]com/path`
- **File Hashes (SHA-256):** `[64-character hash]`

---

## 6. Containment & Remediation Actions
1. **Host-Level Actions:** [e.g., EDR host isolation, process termination, file quarantine]
2. **Network-Level Actions:** [e.g., Perimeter firewall IP/domain blocking]
3. **Identity-Level Actions:** [e.g., Password reset, token revocation, session termination]
4. **Escalation / Next Steps:** [e.g., Handoff to Tier-2 / IR, vendor coordination, root-cause patch]
