# Attack Lifecycle Mapping

Mapping common application security findings to MITRE ATT&CK techniques, showing what happens after the vulnerability is exploited, how to detect each stage, and how to respond.

Most scanners tell you *what* the bug is. This repo maps *what an attacker does with it* once they're through the door.

## Why This Exists

AppSec findings don't exist in a vacuum. A SQL injection isn't just CWE-89. It's initial access, then data collection, then credential theft, then lateral movement. Understanding that chain changes how you prioritize, how you detect, and how you respond.

Each mapping follows the same structure:
- **What the scanner flags** (CWE, OWASP category)
- **ATT&CK techniques enabled** (the full chain, not just initial access)
- **Detection strategy** (what to look for at each stage)
- **Response playbook** (contain, investigate, remediate)

## Mappings

| Vulnerability | Primary ATT&CK Tactic | File |
|--------------|----------------------|------|
| SQL Injection | Initial Access → Collection → Credential Access | [sql-injection.md](mappings/sql-injection.md) |
| Cross-Site Scripting (XSS) | Initial Access → Credential Access → Collection | [xss-cross-site-scripting.md](mappings/xss-cross-site-scripting.md) |
| SSRF | Initial Access → Discovery → Lateral Movement | [ssrf.md](mappings/ssrf.md) |
| Insecure Deserialization | Execution → Persistence → Privilege Escalation | [insecure-deserialization.md](mappings/insecure-deserialization.md) |
| Broken Access Control (IDOR / BOLA) | Discovery → Collection → Privilege Escalation | [broken-access-control.md](mappings/broken-access-control.md) |
| Path Traversal / LFI | Initial Access → Collection → Credential Access | [path-traversal.md](mappings/path-traversal.md) |

### Planned

- Credential Brute Force
- Dependency Exploit (Known CVE)

## References

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [CWE/CAPEC Mapping to ATT&CK](https://capec.mitre.org/)