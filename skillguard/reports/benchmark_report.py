import html
from pathlib import Path
from typing import List
from skillguard.models.report import RepositoryReport, PermissionLevel

def get_severity_color(sev: str) -> str:
    sev = sev.upper()
    if sev == "CRITICAL":
        return "#ef4444"
    elif sev == "HIGH":
        return "#f97316"
    elif sev == "MEDIUM":
        return "#eab308"
    elif sev == "LOW":
        return "#10b981"
    return "#94a3b8"

def get_verdict_pill_style(verdict: str) -> str:
    verdict = verdict.upper()
    if verdict == "SAFE":
        return "background-color: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3);"
    elif verdict == "REVIEW RECOMMENDED":
        return "background-color: rgba(234, 179, 8, 0.15); color: #eab308; border: 1px solid rgba(234, 179, 8, 0.3);"
    elif verdict == "HIGH RISK":
        return "background-color: rgba(249, 115, 22, 0.15); color: #f97316; border: 1px solid rgba(249, 115, 22, 0.3);"
    return "background-color: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3);"

def write_benchmark_report(reports: List[RepositoryReport], output_path: str = "benchmark_report.html") -> Path:
    path = Path(output_path).resolve()
    
    total_repos = len(reports)
    if total_repos > 0:
        avg_trust = int(sum(r.trust_score.overall_score for r in reports) / total_repos)
        max_risk = max(r.score for r in reports)
    else:
        avg_trust = 100
        max_risk = 0

    # Build Comparison Table Rows
    rows = []
    for r in reports:
        pill_style = get_verdict_pill_style(r.verdict)
        risk_color = get_severity_color(r.risk.value)
        
        # Count findings
        crit_count = sum(1 for f in r.findings if f.severity.upper() == "CRITICAL")
        high_count = sum(1 for f in r.findings if f.severity.upper() == "HIGH")
        
        # Permissions summary icons
        pf = r.permission_footprint
        perms = []
        if pf.network_access != PermissionLevel.NONE: perms.append("🌐 Net")
        if pf.filesystem_access != PermissionLevel.NONE: perms.append("📁 File")
        if pf.command_execution != PermissionLevel.NONE: perms.append("💻 Cmd")
        if pf.environment_access != PermissionLevel.NONE: perms.append("🔑 Env")
        perms_str = " ".join(f'<span class="perm-tag">{p}</span>' for p in perms) if perms else '<span class="perm-tag-none">None</span>'
        
        rows.append(f"""
        <tr>
            <td style="font-weight: 600; color: #fff;">{html.escape(r.name)}</td>
            <td><span class="project-tag">{html.escape(r.project_type)}</span></td>
            <td><span class="verdict-pill" style="{pill_style}">{r.verdict}</span></td>
            <td style="font-weight: 700; color: #fff;">{r.trust_score.overall_score}/100</td>
            <td style="font-weight: 700; color: {risk_color};">{r.score}</td>
            <td>{perms_str}</td>
            <td style="color: #94a3b8;">
                {f'<span style="color: #ef4444; font-weight: 600;">{crit_count} Critical</span>' if crit_count > 0 else '0 Crit'} / 
                {f'<span style="color: #f97316; font-weight: 600;">{high_count} High</span>' if high_count > 0 else '0 High'}
            </td>
        </tr>
        """)

    # Detailed Findings sections
    detailed_findings = []
    for r in reports:
        if not r.findings:
            detailed_findings.append(f"""
            <div class="repo-card">
                <h3>{html.escape(r.name)}</h3>
                <p style="color: #10b981; font-weight: 500;">✓ No high/critical vulnerabilities detected.</p>
            </div>
            """)
            continue
            
        findings_html = []
        for f in r.findings:
            sev_color = get_severity_color(f.severity)
            findings_html.append(f"""
            <div class="finding-item" style="border-left: 4px solid {sev_color};">
                <div style="display: flex; gap: 0.5rem; margin-bottom: 0.25rem; font-size: 0.8rem; font-weight: 600;">
                    <span style="color: {sev_color};">{f.severity.upper()}</span>
                    <span style="color: #64748b;">|</span>
                    <span style="color: #38bdf8;">{html.escape(f.category)}</span>
                    <span style="color: #64748b; margin-left: auto;">{html.escape(f.file)}:{f.line}</span>
                </div>
                <p style="color: #f8fafc; font-size: 0.9rem; margin: 0;">{html.escape(f.message)}</p>
            </div>
            """)
            
        detailed_findings.append(f"""
        <div class="repo-card">
            <h3>{html.escape(r.name)} ({len(r.findings)} findings)</h3>
            <div style="display: flex; flex-direction: column; gap: 0.75rem; margin-top: 1rem;">
                {"".join(findings_html)}
            </div>
        </div>
        """)

    template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SkillGuard Benchmark Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Outfit:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-gradient: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            --card-bg: rgba(30, 41, 59, 0.45);
            --card-border: rgba(255, 255, 255, 0.08);
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent: #38bdf8;
        }
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: 'Inter', sans-serif;
            background: #0b0f19;
            background-image: var(--bg-gradient);
            color: var(--text-primary);
            min-height: 100vh;
            padding: 2rem 1rem;
            line-height: 1.5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--card-border);
            padding-bottom: 1.5rem;
        }
        .brand h1 {
            font-family: 'Outfit', sans-serif;
            font-size: 2.2rem;
            font-weight: 700;
            background: linear-gradient(to right, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
        }
        .stat-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            padding: 1.5rem;
            border-radius: 12px;
            backdrop-filter: blur(8px);
        }
        .stat-val {
            font-size: 2.2rem;
            font-weight: 700;
            font-family: 'Outfit', sans-serif;
            color: #fff;
        }
        .stat-label {
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
        }
        .comparison-table-container {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 1.5rem;
            overflow-x: auto;
            backdrop-filter: blur(8px);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }
        th, td {
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.06);
        }
        th {
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }
        .verdict-pill {
            font-size: 0.75rem;
            font-weight: 700;
            padding: 0.25rem 0.6rem;
            border-radius: 6px;
            text-transform: uppercase;
        }
        .project-tag {
            font-size: 0.75rem;
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid rgba(255,255,255,0.06);
            color: var(--text-secondary);
        }
        .perm-tag {
            background: rgba(56, 189, 248, 0.1);
            color: #38bdf8;
            border: 1px solid rgba(56, 189, 248, 0.2);
            font-size: 0.75rem;
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            margin-right: 0.25rem;
        }
        .perm-tag-none {
            color: var(--text-secondary);
            font-size: 0.75rem;
        }
        .findings-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 1.5rem;
        }
        .repo-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            padding: 1.5rem;
            border-radius: 12px;
        }
        .finding-item {
            background: rgba(255,255,255,0.02);
            padding: 0.75rem;
            border-radius: 6px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <h1>SkillGuard Benchmark</h1>
                <p style="color: var(--text-secondary); font-size: 0.9rem; margin-top: 0.25rem;">Multi-Repository Vulnerability Comparison</p>
            </div>
            <div style="text-align: right; font-size: 0.85rem; color: var(--text-secondary);">
                Generated automatically by SkillGuard OSS
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-val">__TOTAL_REPOS__</div>
                <div class="stat-label">Scanned Repositories</div>
            </div>
            <div class="stat-card">
                <div class="stat-val" style="color: #10b981;">__AVG_TRUST__/100</div>
                <div class="stat-label">Average Trust Score</div>
            </div>
            <div class="stat-card">
                <div class="stat-val" style="color: __RISK_COLOR__;">__MAX_RISK__</div>
                <div class="stat-label">Highest Risk Score</div>
            </div>
        </div>

        <div class="comparison-table-container">
            <h2 style="font-family: 'Outfit', sans-serif; font-size: 1.3rem; margin-bottom: 1.25rem;">Repository Overview</h2>
            <table>
                <thead>
                    <tr>
                        <th>Repository</th>
                        <th>Project Type</th>
                        <th>Verdict</th>
                        <th>Trust Score</th>
                        <th>Risk Score</th>
                        <th>Requested Capabilities</th>
                        <th>Vulnerability Count</th>
                    </tr>
                </thead>
                <tbody>
                    __ROWS__
                </tbody>
            </table>
        </div>

        <div class="findings-grid">
            <h2 style="font-family: 'Outfit', sans-serif; font-size: 1.3rem;">Detailed Repository Findings</h2>
            __DETAILED_FINDINGS__
        </div>
    </div>
</body>
</html>"""

    risk_color = get_severity_color("HIGH" if max_risk > 15 else "LOW")

    html_content = template\
        .replace("__TOTAL_REPOS__", str(total_repos))\
        .replace("__AVG_TRUST__", str(avg_trust))\
        .replace("__MAX_RISK__", str(max_risk))\
        .replace("__RISK_COLOR__", risk_color)\
        .replace("__ROWS__", "".join(rows))\
        .replace("__DETAILED_FINDINGS__", "".join(detailed_findings))

    path.write_text(html_content, encoding="utf-8")
    return path
