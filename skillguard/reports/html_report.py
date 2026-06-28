import html
from pathlib import Path
from typing import List

from skillguard.models.finding import Finding
from skillguard.models.report import Report, PermissionLevel, PortfolioSummary, RepositoryReport, PermissionFootprint
from skillguard.core.trust_score import TrustScoreReport

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

def get_level_style(level: str) -> str:
    level = level.upper()
    if level == "HIGH":
        return "background-color: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3);"
    elif level == "MEDIUM":
        return "background-color: rgba(234, 179, 8, 0.15); color: #eab308; border: 1px solid rgba(234, 179, 8, 0.3);"
    elif level == "LOW":
        return "background-color: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3);"
    return "background-color: rgba(255, 255, 255, 0.05); color: rgba(255, 255, 255, 0.35); border: 1px solid rgba(255, 255, 255, 0.08);"

def get_verdict_styles(verdict: str) -> tuple[str, str, str]:
    verdict = verdict.upper()
    if verdict == "SAFE":
        return "rgba(16, 185, 129, 0.06)", "rgba(16, 185, 129, 0.15)", "#10b981"
    elif verdict == "REVIEW RECOMMENDED":
        return "rgba(234, 179, 8, 0.06)", "rgba(234, 179, 8, 0.15)", "#eab308"
    return "rgba(239, 68, 68, 0.06)", "rgba(239, 68, 68, 0.15)", "#ef4444"

def write_html_report(report: Report, trust_report: TrustScoreReport, output_path: str = "report.html") -> Path:
    path = Path(output_path).resolve()
    
    if not report.repositories:
        repo_name = "root"
        if report.evaluation_report:
            import re
            match = re.search(r"Repository:\s*(\w+)", report.evaluation_report.claimed_purpose)
            if match:
                repo_name = match.group(1)
        
        dummy_repo = RepositoryReport(
            name=repo_name,
            path=".",
            score=report.score,
            risk=report.risk,
            trust_score=trust_report,
            permission_footprint=report.permission_footprint or PermissionFootprint(),
            findings=report.findings,
            evaluation_report=report.evaluation_report,
            project_type=report.project_type or "Generic",
            verdict=report.executive_summary.verdict
        )
        report.repositories = [dummy_repo]
    
    # Portfolio Verdict & Banner settings
    portfolio = report.portfolio_summary or PortfolioSummary(
        total_repositories=1,
        total_files=len(report.findings),
        overall_trust_score=trust_report.overall_score,
        overall_risk_score=report.score,
        overall_risk_level=report.risk,
        verdict=report.executive_summary.verdict,
        message=report.executive_summary.message
    )
    
    verdict_bg, verdict_border, badge_color = get_verdict_styles(portfolio.verdict)
    
    # Circular Gauge math
    circumference = 502.6
    offset = circumference - (portfolio.overall_trust_score / 100) * circumference

    # 1. Repository Rankings rows
    rankings_html = []
    for idx, r in enumerate(report.repositories):
        rv_bg, rv_border, rv_color = get_verdict_styles(r.verdict)
        r_style = get_severity_color(r.risk)
        
        rankings_html.append(f"""
        <tr class="ranking-row" onclick="switchRepo({idx})">
            <td style="font-weight: 600; color: #fff;">{html.escape(r.name)}</td>
            <td style="font-family: monospace; font-size: 0.8rem; color: #94a3b8;">{html.escape(r.path)}</td>
            <td><span class="project-tag">{html.escape(r.project_type)}</span></td>
            <td>
                <span class="verdict-pill" style="background-color: {rv_color}15; color: {rv_color}; border: 1px solid {rv_color}30;">
                    {r.verdict}
                </span>
            </td>
            <td style="font-weight: 700; color: {rv_color};">{r.trust_score.overall_score}/100</td>
            <td style="font-weight: 700; color: {r_style};">{r.score}</td>
            <td>
                <span style="color: {r_style}; font-weight: 600; font-size: 0.85rem;">{r.risk.value}</span>
            </td>
        </tr>
        """)

    # 2. Side by Side Listings: Highest Risk & Safest
    high_risk_html = []
    high_risk_repos = [r for r in report.repositories if r.verdict in {"DANGEROUS", "HIGH RISK"}]
    if high_risk_repos:
        for r in high_risk_repos:
            color = "#ef4444"
            high_risk_html.append(f"""
            <li class="list-item" onclick="switchRepo({report.repositories.index(r)})">
                <span style="font-weight: 600;">{html.escape(r.name)}</span>
                <span class="verdict-pill" style="background-color: {color}15; color: {color}; border: 1px solid {color}30;">{r.verdict}</span>
            </li>
            """)
    else:
        high_risk_html.append('<li class="list-item-empty">No dangerous/high risk repositories found.</li>')

    safe_html = []
    safe_repos = [r for r in report.repositories if r.verdict == "SAFE"]
    if safe_repos:
        for r in safe_repos:
            color = "#10b981"
            safe_html.append(f"""
            <li class="list-item" onclick="switchRepo({report.repositories.index(r)})">
                <span style="font-weight: 600;">{html.escape(r.name)}</span>
                <span class="verdict-pill" style="background-color: {color}15; color: {color}; border: 1px solid {color}30;">{r.verdict}</span>
            </li>
            """)
    else:
        safe_html.append('<li class="list-item-empty">No safe repositories found.</li>')

    # 3. Interactive Repository Tabs and Details
    tabs_html = []
    details_html = []
    
    for idx, r in enumerate(report.repositories):
        active_class = "active" if idx == 0 else ""
        rv_bg, rv_border, rv_color = get_verdict_styles(r.verdict)
        
        tabs_html.append(f"""
        <button class="repo-tab {active_class}" onclick="switchRepo({idx})">
            {html.escape(r.name)}
            <span class="tab-badge" style="background-color: {rv_color}15; color: {rv_color}; border: 1px solid {rv_color}30;">{r.verdict}</span>
        </button>
        """)

        # Footprint
        footprint = r.permission_footprint
        capabilities_list = [
            ("Network Access", footprint.network_access.value),
            ("Filesystem Access", footprint.filesystem_access.value),
            ("Environment Access", footprint.environment_access.value),
            ("Database Access", footprint.database_access.value),
            ("Browser Automation", footprint.browser_automation.value),
            ("Command Execution", footprint.command_execution.value),
            ("Container Management", footprint.container_management.value),
            ("Git Operations", footprint.git_operations.value)
        ]
        
        footprint_rows = []
        for name, lvl in capabilities_list:
            lvl_style = get_level_style(lvl)
            checked = "&check;" if lvl != "NONE" else "&times;"
            checked_color = "#38bdf8" if lvl != "NONE" else "rgba(255, 255, 255, 0.15)"
            footprint_rows.append(f"""
            <div class="footprint-row">
                <div style="display: flex; align-items: center; gap: 0.50rem;">
                    <span style="color: {checked_color}; font-weight: 700;">{checked}</span>
                    <span style="font-size: 0.90rem; font-weight: 500; color: rgba(248, 250, 252, 0.85);">{name}</span>
                </div>
                <span class="footprint-lvl-badge" style="{lvl_style}">{lvl}</span>
            </div>
            """)

        # Claim vs Behavior
        eval_card_html = ""
        if r.evaluation_report:
            eval_report = r.evaluation_report
            claimed_tags = "".join(
                f'<span class="project-tag" style="background: rgba(59, 130, 246, 0.1); color: #38bdf8; border: 1px solid rgba(59, 130, 246, 0.2);">{html.escape(c.value)}</span>'
                for c in eval_report.claimed_categories
            )
            
            ob = eval_report.observed_behavior
            behaviors = [
                ("Filesystem Access", ob.filesystem_access),
                ("Network Access", ob.network_access),
                ("Database Access", ob.database_access),
                ("Email Access", ob.email_access),
                ("Browser Automation", ob.browser_automation),
                ("Credential Access", ob.credential_access)
            ]
            ob_items = []
            for b_name, active in behaviors:
                icon = '&check;' if active else '&times;'
                color_style = "color: #f8fafc;" if active else "color: rgba(255,255,255,0.4);"
                ob_items.append(f'<li style="display: flex; align-items: center; gap: 0.5rem; {color_style}">{icon} {b_name}</li>')
                
            mismatch_items = []
            if eval_report.mismatches:
                for m in eval_report.mismatches:
                    mismatch_items.append(f'<div style="display: flex; align-items: flex-start; gap: 0.5rem; color: #ef4444; font-size: 0.9rem; margin-bottom: 0.5rem;"><span>&bull; {html.escape(m)}</span></div>')
            else:
                mismatch_items.append('<div style="display: flex; align-items: center; gap: 0.5rem; color: #10b981; font-size: 0.9rem;"><span>No suspicious mismatches detected</span></div>')

            eval_card_html = f"""
            <div class="card" style="grid-column: span 3; margin-top: 1.5rem;">
                <h2 style="font-family: 'Outfit', sans-serif; font-size: 1.3rem; font-weight: 700; margin-bottom: 1.25rem; border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 0.5rem;">Claim vs Behavior Alignment</h2>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1.5rem;">
                    <div class="sub-card">
                        <h3 class="sub-card-title">Claimed Purpose</h3>
                        <p style="font-size: 0.95rem; line-height: 1.5; color: #fff; font-weight: 500; margin: 0;">{html.escape(eval_report.claimed_purpose)}</p>
                        <div style="margin-top: 1rem; display: flex; flex-wrap: wrap; gap: 0.5rem;">
                            {claimed_tags}
                        </div>
                    </div>
                    <div class="sub-card">
                        <h3 class="sub-card-title">Observed Behavior</h3>
                        <ul style="list-style: none; padding: 0; margin: 0; display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; font-size: 0.85rem;">
                            {"".join(ob_items)}
                        </ul>
                    </div>
                    <div class="sub-card">
                        <h3 class="sub-card-title">Mismatch Detection</h3>
                        <div style="font-weight: 600; font-size: 0.9rem; margin-bottom: 0.5rem; color: #f8fafc;">
                            Verdict: <span style="color: #f97316;">{html.escape(eval_report.verdict)}</span>
                        </div>
                        {"".join(mismatch_items)}
                    </div>
                </div>
            </div>
            """

        # Reasons/Warnings list
        reasons_list = []
        for reason in r.trust_score.reasons:
            if reason.startswith("+"):
                reasons_list.append(f'<li style="display: flex; align-items: center; gap: 0.5rem; color: #10b981; margin-bottom: 0.35rem;">&#43; {html.escape(reason[2:])}</li>')
            else:
                reasons_list.append(f'<li style="display: flex; align-items: center; gap: 0.5rem; color: #eab308; margin-bottom: 0.35rem;">&minus; {html.escape(reason[2:])}</li>')

        # Repo findings
        repo_findings_list = []
        if not r.findings:
            repo_findings_list.append("""
            <div class="no-findings" style="padding: 2.5rem;">
                <p>No security findings (HIGH/CRITICAL) detected in this repository.</p>
            </div>
            """)
        else:
            for f in r.findings:
                sev_color = get_severity_color(f.severity)
                conf_color = "#ef4444" if f.confidence == "HIGH" else ("#eab308" if f.confidence == "MEDIUM" else "#10b981")
                repo_findings_list.append(f"""
                <div class="finding-card" style="margin-bottom: 1rem;">
                    <div class="finding-header">
                        <span class="severity-badge" style="background-color: {sev_color}20; color: {sev_color}; border: 1px solid {sev_color}40;">
                            {f.severity.upper()}
                        </span>
                        <span class="confidence-badge" style="font-size: 0.7rem; font-weight: 700; padding: 0.15rem 0.5rem; border-radius: 4px; background-color: {conf_color}15; color: {conf_color}; border: 1px solid {conf_color}30;">
                            {f.confidence.upper()} CONFIDENCE
                        </span>
                        <span class="finding-category">{html.escape(f.category)}</span>
                        <span class="finding-location" style="margin-left: auto;">{html.escape(f.file)}:{f.line}</span>
                    </div>
                    <div class="finding-body" style="margin-top: 0.5rem;">
                        <p class="finding-msg" style="margin: 0;">{html.escape(f.message)}</p>
                    </div>
                </div>
                """)

        display_style = "display: grid;" if idx == 0 else "display: none;"
        
        details_html.append(f"""
        <div class="repo-details-panel" id="repo-panel-{idx}" style="{display_style} grid-template-columns: 1fr 1.2fr 1fr; gap: 1.5rem; width: 100%;">
            <!-- Score Gauge -->
            <div class="card" style="display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 2rem;">
                <h3 style="font-size: 1.2rem; font-weight: 700; margin-bottom: 1.5rem; color: #f8fafc; text-align: center; font-family: 'Outfit', sans-serif;">Trust score</h3>
                <div class="gauge-container">
                    <svg width="150" height="150" class="gauge-svg">
                        <circle cx="75" cy="75" r="65" class="gauge-bg"></circle>
                        <circle cx="75" cy="75" r="65" class="gauge-fill" style="stroke: {rv_color}; stroke-dasharray: 408.4; stroke-dashoffset: {408.4 - (r.trust_score.overall_score / 100) * 408.4};"></circle>
                    </svg>
                    <div class="gauge-text">
                        <div class="score-num" style="font-size: 2.7rem;">{r.trust_score.overall_score}</div>
                        <div class="score-label" style="font-size: 0.7rem;">Index</div>
                    </div>
                </div>
                <div style="margin-top: 1.25rem; font-size: 0.85rem; color: #94a3b8; font-weight: 500;">
                    Project Profile: <strong>{r.project_type}</strong>
                </div>
                <div style="margin-top: 0.5rem; font-size: 0.85rem; color: #94a3b8; font-weight: 500;">
                    Vulnerability Risk: <strong style="color: {get_severity_color(r.risk)};">{r.risk.value}</strong>
                </div>
            </div>

            <!-- Categories progress & subscores -->
            <div class="card">
                <h3 style="font-size: 1.1rem; font-weight: 700; margin-bottom: 1.25rem; color: #f8fafc; font-family: 'Outfit', sans-serif;">Trust metrics</h3>
                <div class="category-row">
                    <div class="category-header">
                        <span class="category-name">Code Safety</span>
                        <span class="category-score">{r.trust_score.code_safety}%</span>
                    </div>
                    <div class="progress-bar-bg">
                        <div class="progress-bar-fill" style="width: {r.trust_score.code_safety}%; background-color: {get_severity_color('LOW' if r.trust_score.code_safety >= 80 else 'MEDIUM' if r.trust_score.code_safety >= 50 else 'HIGH')};"></div>
                    </div>
                </div>
                <div class="category-row">
                    <div class="category-header">
                        <span class="category-name">Supply Chain Safety</span>
                        <span class="category-score">{r.trust_score.supply_chain_safety}%</span>
                    </div>
                    <div class="progress-bar-bg">
                        <div class="progress-bar-fill" style="width: {r.trust_score.supply_chain_safety}%; background-color: {get_severity_color('LOW' if r.trust_score.supply_chain_safety >= 80 else 'MEDIUM' if r.trust_score.supply_chain_safety >= 50 else 'HIGH')};"></div>
                    </div>
                </div>
                <div class="category-row">
                    <div class="category-header">
                        <span class="category-name">Secrets Hygiene</span>
                        <span class="category-score">{r.trust_score.secrets_hygiene}%</span>
                    </div>
                    <div class="progress-bar-bg">
                        <div class="progress-bar-fill" style="width: {r.trust_score.secrets_hygiene}%; background-color: {get_severity_color('LOW' if r.trust_score.secrets_hygiene >= 80 else 'MEDIUM' if r.trust_score.secrets_hygiene >= 50 else 'HIGH')};"></div>
                    </div>
                </div>
                <div class="category-row">
                    <div class="category-header">
                        <span class="category-name">Network Risk</span>
                        <span class="category-score">{r.trust_score.network_risk}%</span>
                    </div>
                    <div class="progress-bar-bg">
                        <div class="progress-bar-fill" style="width: {r.trust_score.network_risk}%; background-color: {get_severity_color('LOW' if r.trust_score.network_risk >= 80 else 'MEDIUM' if r.trust_score.network_risk >= 50 else 'HIGH')};"></div>
                    </div>
                </div>
                <div class="category-row">
                    <div class="category-header">
                        <span class="category-name">Container Security</span>
                        <span class="category-score">{r.trust_score.container_security}%</span>
                    </div>
                    <div class="progress-bar-bg">
                        <div class="progress-bar-fill" style="width: {r.trust_score.container_security}%; background-color: {get_severity_color('LOW' if r.trust_score.container_security >= 80 else 'MEDIUM' if r.trust_score.container_security >= 50 else 'HIGH')};"></div>
                    </div>
                </div>
            </div>

            <!-- Permission Footprint -->
            <div class="card">
                <h3 style="font-size: 1.1rem; font-weight: 700; margin-bottom: 1.25rem; color: #f8fafc; font-family: 'Outfit', sans-serif;">Permissions</h3>
                <div style="display: flex; flex-direction: column; gap: 0.1rem; max-height: 250px; overflow-y: auto;">
                    {"".join(footprint_rows)}
                </div>
            </div>

            <!-- Claim vs Behavior Card -->
            {eval_card_html}

            <!-- Alignments & Reasons -->
            <div class="card" style="grid-column: span 1.5; margin-top: 1rem;">
                <h3 style="font-size: 1.1rem; font-weight: 700; margin-bottom: 1rem; color: #3b82f6; font-family: 'Outfit', sans-serif;">Explanations</h3>
                <ul style="list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 0.5rem; font-size: 0.9rem;">
                    {"".join(reasons_list) if reasons_list else '<li style="color: rgba(255,255,255,0.4);">No comments available.</li>'}
                </ul>
            </div>

            <!-- Core Risks / Findings specific to Repo -->
            <div class="card" style="grid-column: span 1.5; margin-top: 1rem; max-height: 400px; overflow-y: auto;">
                <h3 style="font-size: 1.1rem; font-weight: 700; margin-bottom: 1rem; color: #ef4444; font-family: 'Outfit', sans-serif;">Security findings (HIGH/CRITICAL)</h3>
                {"".join(repo_findings_list)}
            </div>
        </div>
        """)

    # 4. Top core findings across all repositories
    top_findings_html = []
    if not report.findings:
        top_findings_html.append("""
        <div class="no-findings">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
            <p>No high/critical security findings across any scanned repositories.</p>
        </div>
        """)
    else:
        for idx, f in enumerate(report.findings):
            color = get_severity_color(f.severity)
            conf_color = "#ef4444" if f.confidence == "HIGH" else ("#eab308" if f.confidence == "MEDIUM" else "#10b981")
            
            # Find repo name
            repo_name = "Unknown"
            f_path = Path(f.file).resolve()
            for r in report.repositories:
                r_path = Path(r.path).resolve()
                if r_path == f_path or r_path in f_path.parents:
                    repo_name = r.name
                    break
                    
            top_findings_html.append(f"""
            <div class="finding-card" data-severity="{f.severity.upper()}">
                <div class="finding-header">
                    <span class="severity-badge" style="background-color: {color}25; color: {color}; border: 1px solid {color}40;">
                        {f.severity.upper()}
                    </span>
                    <span class="confidence-badge" style="font-size: 0.75rem; font-weight: 700; padding: 0.2rem 0.6rem; border-radius: 4px; background-color: {conf_color}15; color: {conf_color}; border: 1px solid {conf_color}30;">
                        {f.confidence.upper()} CONFIDENCE
                    </span>
                    <span class="project-tag" style="background: rgba(255, 255, 255, 0.05); color: #f8fafc; border: 1px solid rgba(255,255,255,0.08);">{html.escape(repo_name)}</span>
                    <span class="finding-category">{html.escape(f.category)}</span>
                    <span class="finding-location" style="margin-left: auto;">{html.escape(f.file)}:{f.line}</span>
                </div>
                <div class="finding-body">
                    <p class="finding-msg">{html.escape(f.message)}</p>
                </div>
            </div>
            """)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SkillGuard Portfolio Security Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Outfit:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-gradient: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            --card-bg: rgba(30, 41, 59, 0.45);
            --card-border: rgba(255, 255, 255, 0.08);
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent: #38bdf8;
            --accent-glow: rgba(56, 189, 248, 0.15);
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: 'Inter', sans-serif;
            background: #0b0f19;
            background-image: var(--bg-gradient);
            color: var(--text-primary);
            min-height: 100vh;
            padding: 2rem 1rem;
            line-height: 1.5;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }}

        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--card-border);
            padding-bottom: 1.5rem;
            flex-wrap: wrap;
            gap: 1rem;
        }}

        .brand h1 {{
            font-family: 'Outfit', sans-serif;
            font-size: 2.2rem;
            font-weight: 700;
            background: linear-gradient(to right, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -0.02em;
        }}

        .brand p {{
            color: var(--text-secondary);
            font-size: 0.95rem;
            margin-top: 0.25rem;
        }}

        .scan-meta {{
            text-align: right;
            font-size: 0.85rem;
            color: var(--text-secondary);
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }}

        /* Executive Summary Banner */
        .summary-banner {{
            background: {verdict_bg};
            border: 1px solid {verdict_border};
            border-radius: 16px;
            padding: 1.5rem;
            display: flex;
            align-items: center;
            gap: 1.25rem;
            backdrop-filter: blur(10px);
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.2);
            margin-bottom: 0.5rem;
        }}

        .verdict-badge {{
            font-family: 'Outfit', sans-serif;
            font-size: 1.1rem;
            font-weight: 700;
            padding: 0.5rem 1.25rem;
            border-radius: 8px;
            background-color: {badge_color};
            color: #0f172a;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            box-shadow: 0 4px 14px {badge_color}40;
        }}

        .verdict-pill {{
            font-size: 0.75rem;
            font-weight: 700;
            padding: 0.25rem 0.6rem;
            border-radius: 6px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            display: inline-block;
        }}

        .project-tag {{
            font-size: 0.75rem;
            font-weight: 600;
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid rgba(255,255,255,0.06);
            color: var(--text-secondary);
        }}

        /* Grid layouts */
        .dashboard {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 1.5rem;
        }}

        .card {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 1.5rem;
            backdrop-filter: blur(12px);
            box-shadow: 0 4px 24px rgba(0, 0, 0, 0.15);
            transition: border-color 0.3s ease;
        }}

        .card:hover {{
            border-color: rgba(255, 255, 255, 0.15);
        }}

        .card h2 {{
            font-family: 'Outfit', sans-serif;
            font-size: 1.4rem;
            font-weight: 600;
            margin-bottom: 1.25rem;
            color: var(--text-primary);
        }}

        /* Rankings Table */
        .rankings-section {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 1.5rem;
            backdrop-filter: blur(12px);
            box-shadow: 0 4px 24px rgba(0, 0, 0, 0.15);
        }}

        .rankings-table-container {{
            overflow-x: auto;
            margin-top: 1rem;
        }}

        .rankings-table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.9rem;
        }}

        .rankings-table th, .rankings-table td {{
            padding: 0.85rem 1rem;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }}

        .rankings-table th {{
            font-family: 'Outfit', sans-serif;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }}

        .ranking-row {{
            cursor: pointer;
            transition: background-color 0.2s ease;
        }}

        .ranking-row:hover {{
            background-color: rgba(255, 255, 255, 0.02);
        }}

        /* Lists */
        .list-card {{
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }}

        .list-items {{
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 0.6rem;
        }}

        .list-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.65rem 0.85rem;
            background: rgba(255,255,255,0.02);
            border: 1px solid rgba(255,255,255,0.04);
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s ease;
        }}

        .list-item:hover {{
            background: rgba(255,255,255,0.05);
            border-color: rgba(255,255,255,0.1);
        }}

        .list-item-empty {{
            color: var(--text-secondary);
            font-size: 0.85rem;
            font-style: italic;
            padding: 0.5rem;
        }}

        /* Tabs and Details selector */
        .tabs-container {{
            display: flex;
            gap: 0.5rem;
            overflow-x: auto;
            padding-bottom: 0.5rem;
            margin-bottom: 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.06);
        }}

        .repo-tab {{
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--card-border);
            color: var(--text-secondary);
            padding: 0.5rem 1rem;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 500;
            font-size: 0.85rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            transition: all 0.2s ease;
            white-space: nowrap;
        }}

        .repo-tab:hover {{
            background: rgba(255, 255, 255, 0.06);
            color: var(--text-primary);
        }}

        .repo-tab.active {{
            background: rgba(56, 189, 248, 0.1);
            border-color: var(--accent);
            color: var(--accent);
            font-weight: 600;
        }}

        .tab-badge {{
            font-size: 0.65rem;
            font-weight: 700;
            padding: 0.1rem 0.35rem;
            border-radius: 4px;
            text-transform: uppercase;
        }}

        /* Sub cards claim align */
        .sub-card {{
            background: rgba(255,255,255,0.02);
            border: 1px solid rgba(255,255,255,0.05);
            padding: 1.25rem;
            border-radius: 12px;
        }}

        .sub-card-title {{
            font-size: 1.1rem;
            color: #3b82f6;
            margin-bottom: 0.75rem;
            font-weight: 600;
        }}

        /* Circular Gauge */
        .gauge-container {{
            position: relative;
            width: 150px;
            height: 150px;
        }}

        .gauge-svg {{
            transform: rotate(-90deg);
        }}

        .gauge-bg {{
            fill: none;
            stroke: rgba(255, 255, 255, 0.04);
            stroke-width: 10;
        }}

        .gauge-fill {{
            fill: none;
            stroke-width: 10;
            stroke-linecap: round;
            transition: stroke-dashoffset 1s ease-in-out;
        }}

        .gauge-text {{
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
        }}

        .gauge-text .score-num {{
            font-family: 'Outfit', sans-serif;
            font-weight: 700;
            line-height: 1;
        }}

        .gauge-text .score-label {{
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.1em;
            margin-top: 0.1rem;
        }}

        /* Progress Bars */
        .category-row {{
            margin-bottom: 1.1rem;
        }}

        .category-header {{
            display: flex;
            justify-content: space-between;
            font-size: 0.85rem;
            margin-bottom: 0.35rem;
        }}

        .category-name {{
            font-weight: 500;
            color: var(--text-secondary);
        }}

        .category-score {{
            font-weight: 600;
            color: var(--text-primary);
        }}

        .progress-bar-bg {{
            height: 6px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 3px;
            overflow: hidden;
        }}

        .progress-bar-fill {{
            height: 100%;
            border-radius: 3px;
            transition: width 1s ease-in-out;
        }}

        /* Permission Footprint */
        .footprint-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.6rem 0;
            border-bottom: 1px solid rgba(255,255,255,0.04);
        }}

        .footprint-lvl-badge {{
            font-size: 0.70rem;
            font-weight: 800;
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
        }}

        /* Section Header & Filters */
        .section-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }}

        .section-header h2 {{
            font-family: 'Outfit', sans-serif;
            font-size: 1.6rem;
            font-weight: 700;
        }}

        .filters {{
            display: flex;
            gap: 0.5rem;
        }}

        .filter-btn {{
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--card-border);
            color: var(--text-secondary);
            padding: 0.4rem 1rem;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.85rem;
            font-weight: 500;
            transition: all 0.2s ease;
        }}

        .filter-btn:hover {{
            background: rgba(255, 255, 255, 0.08);
            color: var(--text-primary);
        }}

        .filter-btn.active {{
            background: var(--accent);
            border-color: var(--accent);
            color: #0f172a;
            font-weight: 600;
            box-shadow: 0 0 10px rgba(56, 189, 248, 0.4);
        }}

        /* Findings Cards */
        .findings-list {{
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }}

        .finding-card {{
            background: rgba(30, 41, 59, 0.25);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 1.25rem;
        }}

        .finding-header {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 0.75rem;
            flex-wrap: wrap;
        }}

        .severity-badge {{
            font-size: 0.75rem;
            font-weight: 700;
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .finding-category {{
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--accent);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .finding-location {{
            font-size: 0.85rem;
            color: var(--text-secondary);
            font-family: monospace;
        }}

        .finding-msg {{
            font-size: 0.95rem;
            color: var(--text-primary);
        }}

        .no-findings {{
            text-align: center;
            padding: 3.5rem;
            background: var(--card-bg);
            border: 1px dashed var(--card-border);
            border-radius: 16px;
        }}

        .no-findings svg {{
            margin-bottom: 1rem;
        }}

        .no-findings p {{
            font-size: 1.1rem;
            color: var(--text-secondary);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <h1>SkillGuard Report</h1>
                <p>Isolated Repository-Level AI Agent Skill & Security Auditor</p>
            </div>
            <div class="scan-meta">
                <p>Scanned Repositories: <strong>{portfolio.total_repositories}</strong></p>
                <p>Total Files: <strong>{portfolio.total_files}</strong></p>
            </div>
        </header>

        <!-- Executive Summary Banner -->
        <div class="summary-banner">
            <span class="verdict-badge">{portfolio.verdict}</span>
            <p style="font-size: 1.05rem; font-weight: 500; color: #f8fafc; margin: 0;">
                {html.escape(portfolio.message)}
            </p>
        </div>

        <!-- Portfolio Statistics Grid -->
        <section class="dashboard">
            <!-- Overall Portfolio Score -->
            <div class="card" style="display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 2rem;">
                <h2 style="margin-bottom: 1.5rem; font-size: 1.3rem; font-family: 'Outfit', sans-serif;">Portfolio Trust Index</h2>
                <div class="gauge-container">
                    <svg width="150" height="150" class="gauge-svg">
                        <circle cx="75" cy="75" r="65" class="gauge-bg"></circle>
                        <circle cx="75" cy="75" r="65" class="gauge-fill" style="stroke: {badge_color}; stroke-dasharray: 408.4; stroke-dashoffset: {offset};"></circle>
                    </svg>
                    <div class="gauge-text">
                        <div class="score-num" style="font-size: 3.2rem;">{portfolio.overall_trust_score}</div>
                        <div class="score-label" style="font-size: 0.75rem;">Average</div>
                    </div>
                </div>
                <div class="risk-badge" style="background-color: {get_severity_color(portfolio.overall_risk_level)}20; color: {get_severity_color(portfolio.overall_risk_level)}; border: 1px solid {get_severity_color(portfolio.overall_risk_level)}40; margin-top: 1rem; font-size: 0.85rem; font-weight: 700; padding: 0.25rem 0.75rem; border-radius: 6px; text-transform: uppercase; display: inline-block; letter-spacing: 0.05em;">
                    {portfolio.overall_risk_level.value} Risk
                </div>
            </div>

            <!-- Stats breakdown -->
            <div class="card list-card">
                <h2>Security Statistics</h2>
                <ul class="list-items" style="gap: 1.1rem;">
                    <li style="display: flex; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.6rem;">
                        <span style="color: var(--text-secondary);">Total Repositories</span>
                        <strong style="color: var(--accent); font-size: 1.1rem;">{portfolio.total_repositories}</strong>
                    </li>
                    <li style="display: flex; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.6rem;">
                        <span style="color: var(--text-secondary);">Total Discovered Files</span>
                        <strong style="color: var(--accent); font-size: 1.1rem;">{portfolio.total_files}</strong>
                    </li>
                    <li style="display: flex; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.6rem;">
                        <span style="color: var(--text-secondary);">Max Repository Risk Score</span>
                        <strong style="color: {get_severity_color(portfolio.overall_risk_level)}; font-size: 1.1rem;">{portfolio.overall_risk_score}</strong>
                    </li>
                </ul>
            </div>

            <!-- Verdict distribution counts -->
            <div class="card list-card">
                <h2>Scan Summary Stats</h2>
                <ul class="list-items" style="gap: 0.8rem;">
                    <li style="display: flex; justify-content: space-between; padding: 0.4rem 0; border-bottom: 1px solid rgba(255,255,255,0.04);">
                        <span style="color: var(--text-secondary); font-size: 0.9rem;">SAFE Repositories</span>
                        <span style="color: #10b981; font-weight: 700;">{len(safe_repos)}</span>
                    </li>
                    <li style="display: flex; justify-content: space-between; padding: 0.4rem 0; border-bottom: 1px solid rgba(255,255,255,0.04);">
                        <span style="color: var(--text-secondary); font-size: 0.9rem;">REVIEW RECOMMENDED</span>
                        <span style="color: #eab308; font-weight: 700;">{len([r for r in report.repositories if r.verdict == "REVIEW RECOMMENDED"])}</span>
                    </li>
                    <li style="display: flex; justify-content: space-between; padding: 0.4rem 0; border-bottom: 1px solid rgba(255,255,255,0.04);">
                        <span style="color: var(--text-secondary); font-size: 0.9rem;">HIGH RISK Repositories</span>
                        <span style="color: #f97316; font-weight: 700;">{len([r for r in report.repositories if r.verdict == "HIGH RISK"])}</span>
                    </li>
                    <li style="display: flex; justify-content: space-between; padding: 0.4rem 0;">
                        <span style="color: var(--text-secondary); font-size: 0.9rem;">DANGEROUS Repositories</span>
                        <span style="color: #ef4444; font-weight: 700;">{len([r for r in report.repositories if r.verdict == "DANGEROUS"])}</span>
                    </li>
                </ul>
            </div>
        </section>

        <!-- Repository Rankings Table -->
        <section class="rankings-section">
            <h2 style="font-family: 'Outfit', sans-serif; font-size: 1.4rem; color: #fff;">Repository Rankings</h2>
            <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 1rem;">Repositories are sorted by Risk Score descending. Click on any row to view its detailed analysis below.</p>
            <div class="rankings-table-container">
                <table class="rankings-table">
                    <thead>
                        <tr>
                            <th>Repository</th>
                            <th>Path</th>
                            <th>Project Profile</th>
                            <th>Verdict</th>
                            <th>Trust Score</th>
                            <th>Risk Score</th>
                            <th>Risk Level</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(rankings_html)}
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Side by side list listings -->
        <section class="dashboard" style="grid-template-columns: 1fr 1fr;">
            <!-- Highest Risk Repos Card -->
            <div class="card list-card">
                <h2 style="color: #ef4444; border-bottom: 1px solid rgba(239, 68, 68, 0.15); padding-bottom: 0.5rem; font-family: 'Outfit', sans-serif; font-size: 1.3rem;">Highest Risk Repositories</h2>
                <ul class="list-items">
                    {"".join(high_risk_html)}
                </ul>
            </div>

            <!-- Safest Repos Card -->
            <div class="card list-card">
                <h2 style="color: #10b981; border-bottom: 1px solid rgba(16, 185, 129, 0.15); padding-bottom: 0.5rem; font-family: 'Outfit', sans-serif; font-size: 1.3rem;">Safest Repositories</h2>
                <ul class="list-items">
                    {"".join(safe_html)}
                </ul>
            </div>
        </section>

        <!-- Interactive Repository Detail Section -->
        <section class="card" id="repo-details-section" style="padding: 1.75rem;">
            <h2 style="font-family: 'Outfit', sans-serif; font-size: 1.5rem; color: #3b82f6; border-bottom: 1px solid rgba(59, 130, 246, 0.15); padding-bottom: 0.75rem; margin-bottom: 1.25rem;">Repository Isolation Details</h2>
            
            <!-- Repository Selector Tabs -->
            <div class="tabs-container">
                {"".join(tabs_html)}
            </div>

            <!-- Repository detail content panels -->
            <div style="display: flex; width: 100%;">
                {"".join(details_html)}
            </div>
        </section>

        <!-- Top Findings Portfolio Section -->
        <section class="findings-section">
            <div class="section-header">
                <h2>Top Findings across Portfolio (HIGH/CRITICAL)</h2>
                <div class="filters">
                    <button class="filter-btn active" onclick="filterFindings('ALL')">All</button>
                    <button class="filter-btn" onclick="filterFindings('CRITICAL')">Critical</button>
                    <button class="filter-btn" onclick="filterFindings('HIGH')">High</button>
                </div>
            </div>

            <div class="findings-list" id="findingsContainer">
                {"".join(top_findings_html)}
            </div>
        </section>
    </div>

    <script>
        function switchRepo(index) {{
            // Deactivate all tabs and panels
            const tabs = document.querySelectorAll('.repo-tab');
            tabs.forEach(tab => tab.classList.remove('active'));
            
            const panels = document.querySelectorAll('.repo-details-panel');
            panels.forEach(panel => panel.style.display = 'none');

            // Activate target tab and panel
            if (tabs[index]) {{
                tabs[index].classList.add('active');
            }}
            if (panels[index]) {{
                panels[index].style.display = 'grid';
            }}
            
            // Scroll to details section smoothly
            document.getElementById('repo-details-section').scrollIntoView({{ behavior: 'smooth', block: 'start' }});
        }}

        function filterFindings(severity) {{
            const buttons = document.querySelectorAll('.filter-btn');
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {{
                if (severity === 'ALL' || card.getAttribute('data-severity') === severity) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
"""
    
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    return path
