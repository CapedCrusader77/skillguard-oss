## 🛡️ SkillGuard Security Scan Report

### 🔍 Verdict: **REVIEW RECOMMENDED**
*Review recommended: Repositories exhibit unexpected capabilities or moderate risk.*

| Metric | Value |
| :--- | :--- |
| **Overall Trust Score** | `85/100` |
| **Overall Risk Score** | `15` (LOW) |
| **Scanned Files** | `174` |

### 🚨 Security Findings

| Severity | Category | Location | Message |
| :---: | :--- | :--- | :--- |
| 🟠 `HIGH` | COMMAND_EXECUTION | `skillguard/core/github_scanner.py:60` | subprocess.run detected |
| 🟢 `LOW` | FILE_SYSTEM | `skillguard/core/repository_discovery.py:73` | os.walk detected |
| 🟢 `LOW` | FILE_SYSTEM | `skillguard/core/repository_discovery.py:106` | os.walk detected |

---
*See the generated build artifacts for full details and HTML dashboards.*
