import sys
from pathlib import Path
from typing import List, Dict, Set
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.align import Align

from skillguard import __version__
from skillguard.core import (
    get_scan_targets, evaluate_risk, calculate_trust_score, group_files_by_repository, TrustScoreReport
)
from skillguard.scanners import scan_file, JavaScriptScanner, TypeScriptScanner, DartScanner
from skillguard.analyzers import analyzer_registry
from skillguard.analysis import (
    RuleBasedClaimExtractor, BehaviorAnalyzer, TrustEvaluator,
    ProjectProfiler, ProjectType, Capability, BehaviorProfile
)
from skillguard.models.finding import Finding
from skillguard.models.report import (
    Report, PermissionLevel, PermissionFootprint, ExecutiveSummary,
    RepositoryReport, PortfolioSummary
)
from skillguard.models.risk import RiskLevel, get_risk_level
from skillguard.reports import write_report_json, write_html_report

# Initialize Rich console
console = Console()

app = typer.Typer(
    name="skillguard",
    help="SkillGuard: Trust but Verify for AI Agent Skills, MCP Servers, and Plugins.",
    add_completion=False
)

@app.command()
def version():
    """
    Print the version of SkillGuard.
    """
    console.print(f"[bold cyan]SkillGuard[/bold cyan] version [bold white]{__version__}[/bold white]")

def get_risk_style(level: RiskLevel) -> str:
    """Returns the rich style associated with the risk level."""
    if level == RiskLevel.LOW:
        return "bold green"
    elif level == RiskLevel.MEDIUM:
        return "bold yellow"
    elif level == RiskLevel.HIGH:
        return "bold red"
    elif level == RiskLevel.CRITICAL:
        return "bold white on red"
    return "white"

def get_confidence_style(conf: str) -> str:
    """Returns the rich style associated with the confidence level."""
    conf = conf.upper()
    if conf == "HIGH":
        return "bold red"
    elif conf == "MEDIUM":
        return "bold yellow"
    return "bold green"

def get_verdict_style(verdict: str) -> str:
    """Returns the rich style associated with the verdict level."""
    verdict = verdict.upper()
    if verdict == "DANGEROUS":
        return "bold white on red"
    elif verdict == "HIGH RISK":
        return "bold red"
    elif verdict == "REVIEW RECOMMENDED":
        return "bold yellow"
    elif verdict == "SAFE":
        return "bold green"
    return "white"

def get_verdict_border_style(verdict: str) -> str:
    """Returns the rich border style associated with the verdict level."""
    verdict = verdict.upper()
    if verdict == "DANGEROUS" or verdict == "HIGH RISK":
        return "red"
    elif verdict == "REVIEW RECOMMENDED":
        return "yellow"
    elif verdict == "SAFE":
        return "green"
    return "white"

def max_level(levels: List[PermissionLevel]) -> PermissionLevel:
    """Returns the maximum permission level from a list."""
    for lvl in [PermissionLevel.HIGH, PermissionLevel.MEDIUM, PermissionLevel.LOW]:
        if lvl in levels:
            return lvl
    return PermissionLevel.NONE

def aggregate_findings(findings: List[Finding]) -> List[Finding]:
    """
    Aggregate duplicate findings in the same file and ID:
    e.g. 14 fetch calls in the same file become a single finding with (14 occurrences) message.
    """
    grouped = {}
    for f in findings:
        key = (f.id, f.file)
        if key not in grouped:
            grouped[key] = []
        grouped[key].append(f)
    
    aggregated = []
    for (fid, file), f_list in grouped.items():
        first = f_list[0]
        count = len(f_list)
        
        if count > 1:
            msg = f"{first.message} ({count} occurrences)"
        else:
            msg = first.message
            
        confidence = "HIGH"
        if any(f.confidence == "HIGH" for f in f_list):
            confidence = "HIGH"
        elif any(f.confidence == "MEDIUM" for f in f_list):
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
            
        aggregated.append(
            Finding(
                id=fid,
                severity=first.severity,
                confidence=confidence,
                category=first.category,
                file=file,
                line=first.line,
                message=msg
            )
        )
    return aggregated

@app.command()
def scan(
    path: Path = typer.Argument(
        ...,
        help="Path to the directory or file to scan",
        exists=True,
        file_okay=True,
        dir_okay=True,
        resolve_path=True,
    ),
    json_report: bool = typer.Option(
        False,
        "--json",
        help="Generate JSON report"
    ),
    html_report: bool = typer.Option(
        False,
        "--html",
        help="Generate HTML report"
    ),
    full: bool = typer.Option(
        False,
        "--full",
        help="Run full analysis (includes AST scanners and all supply chain analyzers)"
    ),
    trust: bool = typer.Option(
        False,
        "--trust",
        help="Evaluate claimed purpose vs observed behavior"
    ),
    output: str = typer.Option(
        "report.json",
        "--output",
        "-o",
        help="Path to save the JSON report if generated"
    )
):
    """
    Scan a repository, directory, or source file recursively for security risks with Repository Isolation.
    """
    console.print()
    header_content = (
        "[bold cyan]SKILLGUARD[/bold cyan]\n"
        "[italic dim]Trust but Verify for AI Agent Skills, MCP Servers, and Plugins[/italic dim]"
    )
    console.print(Panel(Align.center(header_content), border_style="cyan", box=box.ROUNDED))
    console.print()

    # Load files using the repository discovery engine
    try:
        files, lang_stats, repo_count = get_scan_targets(path)
    except Exception as e:
        console.print(f"[bold red]Error during file discovery:[/] {e}")
        raise typer.Exit(code=1)

    if not files:
        console.print("[yellow]WARNING: No supported files found to scan.[/yellow]")
        raise typer.Exit(code=0)

    # Detect repository boundaries and group files
    from skillguard.core.repository_discovery import discover_files
    try:
        _, git_repos = discover_files(path)
        repo_files_map = group_files_by_repository(path, files, git_repos)
    except Exception as e:
        console.print(f"[bold red]Error during repository grouping:[/] {e}")
        raise typer.Exit(code=1)

    # Output repository discovery info
    console.print(f"Found [bold cyan]{len(repo_files_map)}[/bold cyan] repositories")
    console.print(f"Found [bold cyan]{len(files)}[/bold cyan] source files")
    console.print()
    for lang, count in lang_stats.items():
        console.print(f"{lang}: [bold]{count}[/bold]")
    console.print()
    
    analysis_type = "Full Analysis" if full else "Code AST Analysis"
    console.print(f"[bold blue]Beginning {analysis_type}...[/bold blue]")
    console.print()

    profiler = ProjectProfiler()
    repositories_reports: List[RepositoryReport] = []

    # Execute isolated repository scans
    for repo_root, repo_files in repo_files_map.items():
        repo_name = repo_root.name or repo_root.resolve().name or "root"
        with console.status(f"[bold blue]Scanning repository: {repo_name}...", spinner="dots"):
            repo_findings = []
            
            # Execute AST scanners for this repo's files
            for file_path in repo_files:
                try:
                    ext = file_path.suffix.lower()
                    if ext == ".py":
                        file_findings = scan_file(file_path, repo_root)
                    elif ext == ".js":
                        file_findings = JavaScriptScanner(file_path, repo_root).scan()
                    elif ext == ".ts":
                        file_findings = TypeScriptScanner(file_path, repo_root).scan()
                    elif ext == ".dart":
                        file_findings = DartScanner(file_path, repo_root).scan()
                    else:
                        file_findings = []
                    repo_findings.extend(file_findings)
                except Exception as e:
                    console.print(f"[dim red]Error scanning {file_path.name} in {repo_name}: {e}[/]")

            # Execute plugin supply chain analyzers if --full is set
            if full:
                for analyzer in analyzer_registry:
                    try:
                        analyzer_findings = analyzer.analyze(repo_root)
                        repo_findings.extend(analyzer_findings)
                    except Exception as e:
                        console.print(f"[dim red]Error running {analyzer.__class__.__name__} on {repo_name}: {e}[/]")

            # Classify project type
            repo_project_type = profiler.profile_project(repo_root)

            # Evaluate results with context-awareness over repo findings list
            repo_score, repo_risk_level = evaluate_risk(repo_findings, repo_root)
            repo_trust_report = calculate_trust_score(repo_findings, repo_root)

            # Calculate active capabilities & permission footprint
            try:
                repo_behavior = BehaviorAnalyzer().analyze_behavior(repo_root, repo_findings)
            except Exception:
                repo_behavior = None
                
            net_level = PermissionLevel.NONE
            if repo_behavior and repo_behavior.network_access:
                net_rules = {f.id for f in repo_findings if f.category == "NETWORK"}
                if any(r in {"NET001", "NET003", "NET004", "NET005", "NET007", "NET102"} for r in net_rules):
                    net_level = PermissionLevel.HIGH
                else:
                    net_level = PermissionLevel.MEDIUM
            elif any(f.id == "NET201" for f in repo_findings):
                net_level = PermissionLevel.MEDIUM

            filesystem_level = PermissionLevel.NONE
            if repo_behavior and repo_behavior.filesystem_access:
                file_rules = {f.id for f in repo_findings if f.category == "FILE_SYSTEM"}
                if any(r in {"FIL003", "FIL102", "DKR005"} for r in file_rules):
                    filesystem_level = PermissionLevel.HIGH
                else:
                    filesystem_level = PermissionLevel.MEDIUM

            environment_level = PermissionLevel.NONE
            if repo_behavior and repo_behavior.credential_access:
                environment_level = PermissionLevel.HIGH
            elif any(f.category == "SECRET_ACCESS" or f.id in {"SEC001", "SEC002", "SEC102"} for f in repo_findings):
                environment_level = PermissionLevel.MEDIUM

            database_level = PermissionLevel.NONE
            if repo_behavior and repo_behavior.database_access:
                database_level = PermissionLevel.HIGH
            elif "db" in str([f.message for f in repo_findings]).lower():
                database_level = PermissionLevel.MEDIUM

            browser_level = PermissionLevel.NONE
            if repo_behavior and repo_behavior.browser_automation:
                browser_level = PermissionLevel.HIGH

            command_level = PermissionLevel.NONE
            cmd_rules = {f.id for f in repo_findings if f.category == "COMMAND_EXECUTION"}
            if cmd_rules:
                command_level = PermissionLevel.HIGH

            container_level = PermissionLevel.NONE
            docker_rules = {f.id for f in repo_findings if f.id.startswith("DKR")}
            if docker_rules:
                if any(r in {"DKR003", "DKR005", "DKR006"} for r in docker_rules):
                    container_level = PermissionLevel.HIGH
                else:
                    container_level = PermissionLevel.MEDIUM

            git_level = PermissionLevel.NONE
            gha_rules = {f.id for f in repo_findings if f.id.startswith("GHA")}
            if gha_rules:
                if any(r in {"GHA001", "GHA003"} for r in gha_rules):
                    git_level = PermissionLevel.HIGH
                else:
                    git_level = PermissionLevel.MEDIUM

            repo_footprint = PermissionFootprint(
                network_access=net_level,
                filesystem_access=filesystem_level,
                environment_access=environment_level,
                database_access=database_level,
                browser_automation=browser_level,
                command_execution=command_level,
                container_management=container_level,
                git_operations=git_level
            )

            # Separate capabilities from vulnerabilities (Keep only HIGH/CRITICAL in reported findings)
            repo_security_findings = [f for f in repo_findings if f.severity.upper() in {"HIGH", "CRITICAL"}]

            # Evaluate Claim vs Behavior
            repo_eval = None
            if trust or full:
                try:
                    repo_claims = RuleBasedClaimExtractor().extract_claims(repo_root)
                    repo_eval = TrustEvaluator().evaluate(repo_claims, repo_behavior or BehaviorProfile())
                except Exception as e:
                    console.print(f"[dim red]Error during claim/behavior evaluation on {repo_name}: {e}[/]")

            # Verdict Logic:
            # Trust >= 85 and Risk LOW => SAFE
            # Trust 60-84 => REVIEW RECOMMENDED
            # Trust < 60 => HIGH RISK
            # Trust < 40 => DANGEROUS
            t_val = repo_trust_report.overall_score
            if repo_eval is not None:
                t_val = min(t_val, repo_eval.trust_score)

            has_repo_critical = any(f.severity.upper() == "CRITICAL" for f in repo_security_findings)
            has_repo_high = any(f.severity.upper() == "HIGH" for f in repo_security_findings)

            if t_val < 40 or has_repo_critical:
                repo_verdict = "DANGEROUS"
            elif t_val < 60:
                repo_verdict = "HIGH RISK"
            elif t_val >= 85 and repo_risk_level == RiskLevel.LOW and not has_repo_high:
                repo_verdict = "SAFE"
            else:
                repo_verdict = "REVIEW RECOMMENDED"

            repo_report = RepositoryReport(
                name=repo_name,
                path=str(repo_root.resolve().as_posix()),
                score=repo_score,
                risk=repo_risk_level,
                trust_score=repo_trust_report,
                permission_footprint=repo_footprint,
                findings=repo_security_findings,
                evaluation_report=repo_eval,
                project_type=repo_project_type.value,
                verdict=repo_verdict
            )
            repositories_reports.append(repo_report)

    # Sort repositories by risk score descending
    repositories_reports.sort(key=lambda r: r.score, reverse=True)

    # Calculate overall Portfolio metrics
    total_repos = len(repositories_reports)
    total_files = len(files)
    if total_repos > 0:
        overall_trust = int(sum(r.trust_score.overall_score for r in repositories_reports) / total_repos)
        overall_risk_score = max(r.score for r in repositories_reports)
    else:
        overall_trust = 100
        overall_risk_score = 0
    overall_risk_lvl = get_risk_level(overall_risk_score)

    # Portfolio Verdict Logic
    # Remove global DANGEROUS verdicts unless the overall portfolio is actually dangerous:
    # Portfolio is DANGEROUS if any repo is DANGEROUS or overall trust < 40.
    has_critical_anywhere = any(any(f.severity.upper() == "CRITICAL" for f in r.findings) for r in repositories_reports)
    if any(r.verdict == "DANGEROUS" for r in repositories_reports) or overall_trust < 40 or has_critical_anywhere:
        overall_verdict = "DANGEROUS"
        overall_message = "The portfolio contains dangerous repositories with severe security exploits."
    elif any(r.verdict == "HIGH RISK" for r in repositories_reports) or overall_trust < 60:
        overall_verdict = "HIGH RISK"
        overall_message = "One or more repositories contain high risk findings."
    elif any(r.verdict == "REVIEW RECOMMENDED" for r in repositories_reports) or overall_trust < 85:
        overall_verdict = "REVIEW RECOMMENDED"
        overall_message = "Review recommended: Repositories exhibit unexpected capabilities or moderate risk."
    else:
        overall_verdict = "SAFE"
        overall_message = "All repositories are safe and conform to expected behavior profiles."

    portfolio_summary = PortfolioSummary(
        total_repositories=total_repos,
        total_files=total_files,
        overall_trust_score=overall_trust,
        overall_risk_score=overall_risk_score,
        overall_risk_level=overall_risk_lvl,
        verdict=overall_verdict,
        message=overall_message
    )

    # Flat aggregated findings and portfolio trust reports for backward compatibility
    all_flat_findings: List[Finding] = []
    for r in repositories_reports:
        all_flat_findings.extend(r.findings)

    if total_repos > 0:
        avg_code = int(sum(r.trust_score.code_safety for r in repositories_reports) / total_repos)
        avg_chain = int(sum(r.trust_score.supply_chain_safety for r in repositories_reports) / total_repos)
        avg_secrets = int(sum(r.trust_score.secrets_hygiene for r in repositories_reports) / total_repos)
        avg_net = int(sum(r.trust_score.network_risk for r in repositories_reports) / total_repos)
        avg_container = int(sum(r.trust_score.container_security for r in repositories_reports) / total_repos)
    else:
        avg_code = avg_chain = avg_secrets = avg_net = avg_container = 100

    all_reasons = []
    all_risks = []
    all_behaviors = []
    for r in repositories_reports:
        all_reasons.extend(r.trust_score.reasons)
        all_risks.extend(r.trust_score.top_risks)
        all_behaviors.extend(r.trust_score.most_common_behaviors)

    portfolio_trust_report = TrustScoreReport(
        overall_score=overall_trust,
        code_safety=avg_code,
        supply_chain_safety=avg_chain,
        secrets_hygiene=avg_secrets,
        network_risk=avg_net,
        container_security=avg_container,
        reasons=list(set(all_reasons)),
        top_risks=list(set(all_risks)),
        most_common_behaviors=list(set(all_behaviors))
    )

    portfolio_footprint = PermissionFootprint(
        network_access=max_level([r.permission_footprint.network_access for r in repositories_reports]) if repositories_reports else PermissionLevel.NONE,
        filesystem_access=max_level([r.permission_footprint.filesystem_access for r in repositories_reports]) if repositories_reports else PermissionLevel.NONE,
        environment_access=max_level([r.permission_footprint.environment_access for r in repositories_reports]) if repositories_reports else PermissionLevel.NONE,
        database_access=max_level([r.permission_footprint.database_access for r in repositories_reports]) if repositories_reports else PermissionLevel.NONE,
        browser_automation=max_level([r.permission_footprint.browser_automation for r in repositories_reports]) if repositories_reports else PermissionLevel.NONE,
        command_execution=max_level([r.permission_footprint.command_execution for r in repositories_reports]) if repositories_reports else PermissionLevel.NONE,
        container_management=max_level([r.permission_footprint.container_management for r in repositories_reports]) if repositories_reports else PermissionLevel.NONE,
        git_operations=max_level([r.permission_footprint.git_operations for r in repositories_reports]) if repositories_reports else PermissionLevel.NONE
    )

    report = Report(
        score=overall_risk_score,
        risk=overall_risk_lvl,
        findings=all_flat_findings,
        trust_score=portfolio_trust_report,
        evaluation_report=None,
        project_type="Portfolio",
        permission_footprint=portfolio_footprint,
        executive_summary=ExecutiveSummary(verdict=overall_verdict, message=overall_message),
        repositories=repositories_reports,
        portfolio_summary=portfolio_summary
    )

    # Write JSON report
    json_path = None
    if json_report or (not html_report):
        try:
            json_path = write_report_json(report, output)
        except Exception as e:
            console.print(f"[bold red]Error saving JSON report:[/] {e}")

    # Write HTML report
    html_path = None
    if html_report:
        try:
            html_path = write_html_report(report, portfolio_trust_report, "report.html")
        except Exception as e:
            console.print(f"[bold red]Error saving HTML report:[/] {e}")

    # 1. Output Portfolio Summary
    verdict_style = get_verdict_style(overall_verdict)
    verdict_border = get_verdict_border_style(overall_verdict)
    summary_text = (
        f"Verdict: [{verdict_style}] {overall_verdict} [/{verdict_style}]\n"
        f"Message: [italic]{overall_message}[/italic]\n\n"
        f"Total Repositories: [bold cyan]{total_repos}[/bold cyan]\n"
        f"Total Source Files: [bold cyan]{total_files}[/bold cyan]\n"
        f"Overall Trust Score: [bold]{overall_trust}/100[/bold]\n"
        f"Overall Risk Score: [bold]{overall_risk_score}[/bold] ({overall_risk_lvl.value})"
    )
    console.print(
        Panel(
            summary_text,
            title="Portfolio Summary",
            border_style=verdict_border,
            box=box.ROUNDED,
            expand=False
        )
    )
    console.print()

    # 2. Output Repository Rankings
    console.print("[bold cyan]Repository Rankings (Highest Risk First):[/bold cyan]")
    rankings_table = Table(box=box.ROUNDED, border_style="dim")
    rankings_table.add_column("Repository", style="bold white")
    rankings_table.add_column("Verdict", justify="center")
    rankings_table.add_column("Project Type", style="cyan")
    rankings_table.add_column("Trust Score", justify="center", style="bold")
    rankings_table.add_column("Risk Score", justify="center", style="bold")
    rankings_table.add_column("Risk Level", justify="center")
    
    for r in repositories_reports:
        rv_style = get_verdict_style(r.verdict)
        rv_text = f"[{rv_style}] {r.verdict} [/{rv_style}]"
        
        rr_style = get_risk_style(r.risk)
        rr_text = f"[{rr_style}] {r.risk.value} [/{rr_style}]"
        
        rankings_table.add_row(
            r.name,
            rv_text,
            r.project_type,
            f"{r.trust_score.overall_score}/100",
            str(r.score),
            rr_text
        )
    console.print(rankings_table)
    console.print()

    # 3. Output Highest Risk Repositories
    console.print("[bold red]Highest Risk Repositories:[/bold red]")
    high_risk_repos = [r for r in repositories_reports if r.verdict in {"DANGEROUS", "HIGH RISK"}]
    if high_risk_repos:
        for r in high_risk_repos:
            rv_style = get_verdict_style(r.verdict)
            console.print(f"  • [bold white]{r.name}[/bold white] - [{rv_style}]{r.verdict}[/{rv_style}] (Trust: {r.trust_score.overall_score}, Risk: {r.score})")
    else:
        console.print("  (None)")
    console.print()

    # 4. Output Safest Repositories
    console.print("[bold green]Safest Repositories:[/bold green]")
    safe_repos = [r for r in repositories_reports if r.verdict == "SAFE"]
    if safe_repos:
        for r in safe_repos:
            console.print(f"  • [bold white]{r.name}[/bold white] - [bold green]SAFE[/bold green] (Trust: {r.trust_score.overall_score}, Risk: {r.score})")
    else:
        console.print("  (None)")
    console.print()

    # 5. Output Top Findings
    if not all_flat_findings:
        console.print(
            Panel(
                "[bold green]No security issues or dangerous patterns detected across any repository![/]",
                border_style="green",
                box=box.ROUNDED
            )
        )
    else:
        console.print("[bold red]Top Findings (HIGH/CRITICAL):[/]")
        console.print()
        
        findings_table = Table(box=box.ROUNDED, border_style="dim")
        findings_table.add_column("Repository", style="bold white")
        findings_table.add_column("Severity", justify="center", style="bold")
        findings_table.add_column("Confidence", justify="center", style="bold")
        findings_table.add_column("Category", style="cyan")
        findings_table.add_column("Location", style="dim green")
        findings_table.add_column("Message", style="white")

        # Aggregate findings
        aggregated = aggregate_findings(all_flat_findings)

        for f in aggregated:
            # Match repo
            repo_name = "Unknown"
            f_path = Path(f.file).resolve()
            for r in repositories_reports:
                r_path = Path(r.path).resolve()
                if r_path == f_path or r_path in f_path.parents:
                    repo_name = r.name
                    break
                    
            sev_style = get_risk_style(RiskLevel(f.severity))
            sev_text = f"[{sev_style}]{f.severity}[/{sev_style}]"
            
            conf_style = get_confidence_style(f.confidence)
            conf_text = f"[{conf_style}]{f.confidence}[/{conf_style}]"
            
            findings_table.add_row(
                repo_name,
                sev_text,
                conf_text,
                f.category,
                f"{f.file}:{f.line}",
                f.message
            )
        console.print(findings_table)
        console.print()

    # 6. Output Claim vs Behavior details if run
    for r in repositories_reports:
        if r.evaluation_report:
            eval_rep = r.evaluation_report
            categories_str = ", ".join(c.value for c in eval_rep.claimed_categories)
            
            # Format observed behaviors list
            behaviors = []
            if eval_rep.observed_behavior.network_access: behaviors.append("Network Access")
            if eval_rep.observed_behavior.filesystem_access: behaviors.append("Filesystem Access")
            if eval_rep.observed_behavior.credential_access: behaviors.append("Credential Access")
            if eval_rep.observed_behavior.database_access: behaviors.append("Database Access")
            if eval_rep.observed_behavior.email_access: behaviors.append("Email Access")
            if eval_rep.observed_behavior.browser_automation: behaviors.append("Browser Automation")
            
            behavior_str = "\n".join(f"  ✓ {b}" for b in behaviors) if behaviors else "  ✓ None"
            warnings_str = "\n".join(f"  ⚠️ {m}" for m in eval_rep.mismatches) if eval_rep.mismatches else "  ✓ None"
            
            trust_style = "bold green" if eval_rep.trust_score >= 80 else ("bold yellow" if eval_rep.trust_score >= 50 else "bold red")
            
            trust_text = (
                f"Claimed Purpose:\n  [bold cyan]{eval_rep.claimed_purpose}[/bold cyan] ({categories_str})\n\n"
                f"Observed Behavior:\n{behavior_str}\n\n"
                f"Warnings:\n{warnings_str}\n\n"
                f"Verdict: [{trust_style}]{eval_rep.verdict} ({eval_rep.trust_score}/100)[/{trust_style}]"
            )
            
            console.print(
                Panel(
                    trust_text,
                    title=f"[bold]Claim vs Behavior Evaluation: {r.name}[/bold]",
                    border_style="cyan",
                    box=box.ROUNDED
                )
            )
            console.print()

    if json_path:
        console.print(f"Report saved to: [bold underline]{json_path}[/]")
    if html_path:
        console.print(f"HTML Report saved to: [bold underline]{html_path}[/]")
    console.print()

    # Exit with code 1 if overall portfolio verdict is DANGEROUS
    if overall_verdict == "DANGEROUS":
        raise typer.Exit(code=1)
    else:
        raise typer.Exit(code=0)

if __name__ == "__main__":
    app()
