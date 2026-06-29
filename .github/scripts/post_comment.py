import json
import os
import subprocess
from pathlib import Path

def main():
    report_file = Path("report.json")
    if not report_file.exists():
        print("report.json not found.")
        return

    with open(report_file, "r") as f:
        data = json.load(f)

    # Extract portfolio summary details
    portfolio = data.get("portfolio_summary", {})
    if not portfolio:
        # Fallback to single repository report structure
        verdict = data.get("executive_summary", {}).get("verdict", "UNKNOWN")
        message = data.get("executive_summary", {}).get("message", "")
        trust_score = data.get("trust_score", {}).get("overall_score", 100)
        risk_score = data.get("score", 0)
        risk_lvl = data.get("risk", "LOW")
        total_files = len(data.get("findings", []))
    else:
        verdict = portfolio.get("verdict", "UNKNOWN")
        message = portfolio.get("message", "")
        trust_score = portfolio.get("overall_trust_score", 100)
        risk_score = portfolio.get("overall_risk_score", 0)
        risk_lvl = portfolio.get("overall_risk_level", "LOW")
        total_files = portfolio.get("total_files", 0)

    # Determine verdict emoji
    emoji = "✅"
    if verdict == "DANGEROUS":
        emoji = "❌"
    elif verdict == "HIGH RISK":
        emoji = "⚠️"
    elif verdict == "REVIEW RECOMMENDED":
        emoji = "🔍"

    comment_lines = [
        "## 🛡️ SkillGuard Security Scan Report",
        "",
        f"### {emoji} Verdict: **{verdict}**",
        f"*{message}*",
        "",
        "| Metric | Value |",
        "| :--- | :--- |",
        f"| **Overall Trust Score** | `{trust_score}/100` |",
        f"| **Overall Risk Score** | `{risk_score}` ({risk_lvl}) |",
        f"| **Scanned Files** | `{total_files}` |",
        "",
    ]

    findings = data.get("findings", [])
    if not findings:
        comment_lines.append("### ✨ No security issues or dangerous patterns detected!")
    else:
        comment_lines.extend([
            "### 🚨 Security Findings",
            "",
            "| Severity | Category | Location | Message |",
            "| :---: | :--- | :--- | :--- |"
        ])
        
        # Sort findings: CRITICAL/HIGH first
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "LOW").upper(), 4))
        
        for f in sorted_findings:
            sev = f.get("severity", "LOW").upper()
            cat = f.get("category", "")
            location = f"{f.get('file', '')}:{f.get('line', '')}"
            msg = f.get("message", "")
            
            # Emoji for severity
            sev_badge = f" `{sev}`"
            if sev == "CRITICAL":
                sev_badge = "🔴 `CRITICAL`"
            elif sev == "HIGH":
                sev_badge = "🟠 `HIGH`"
            elif sev == "MEDIUM":
                sev_badge = "🟡 `MEDIUM`"
            elif sev == "LOW":
                sev_badge = "🟢 `LOW`"
                
            comment_lines.append(f"| {sev_badge} | {cat} | `{location}` | {msg} |")

    comment_body = "\n".join(comment_lines)
    
    # Write comment body to temp file
    comment_file = Path("pr_comment.md")
    comment_file.write_text(comment_body, encoding="utf-8")
    
    # Use GitHub CLI to post the comment
    # The action runner automatically populates GITHUB_EVENT_PATH
    event_path = os.getenv("GITHUB_EVENT_PATH")
    if event_path:
        with open(event_path, "r") as ef:
            event_data = json.load(ef)
        pr_number = event_data.get("pull_request", {}).get("number")
        if pr_number:
            print(f"Posting comment to PR #{pr_number}...")
            subprocess.run([
                "gh", "pr", "comment", str(pr_number), "--body-file", "pr_comment.md"
            ], check=True)
            print("PR comment posted successfully.")
        else:
            print("No PR number found in GITHUB_EVENT_PATH.")
    else:
        print("GITHUB_EVENT_PATH not set. Skipping PR comment.")

if __name__ == "__main__":
    main()
