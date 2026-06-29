# 🛡️ SkillGuard

> **"Trust but Verify for AI Agent Skills, MCP Servers, and Plugins."**

SkillGuard scans AI agent plugins, MCP (Model Context Protocol) servers, and custom agent skills before installation. It identifies security vulnerabilities, dangerous behaviors, and permission mismatches via AST static analysis and comprehensive supply chain checks.

The ultimate long-term goal of SkillGuard is to become the **"VirusTotal for AI Agent Tools."**

---

## ✨ Features

- **AST-Based Source Code Scanning**: Parses Python, JavaScript, and TypeScript source files recursively to track imports, aliases, and dangerous API calls without using brittle regex parsing for code logic.
- **Repository Discovery Engine**: Automatically walks directories, groups files by language, skips dependencies (e.g. `node_modules`, `.venv`), and identifies repository counts.
- **Supply Chain Security Analyzers**:
  - **Dependency Analyzer**: Scans requirements manifests and package lockfiles for typosquatting (e.g. `requestss`), duplicate dependencies, and excessive system permissions.
  - **Dockerfile Analyzer**: Flags root execution, unsafe file permissions (`chmod 777`), remote script execution, and unpinned dependencies during container builds.
  - **GitHub Actions Analyzer**: Scans workflow files for remote scripts downloads, actions unpinned to Git commit SHAs, and secrets exposure in environment declarations.
  - **Secret Analyzer**: Searches the codebase recursively for exposed API keys (OpenAI, AWS, GitHub PATs, Google API keys), JWT/Bearer tokens, and hardcoded variables.
  - **Network Destination Analyzer**: Automatically extracts outbound domains, hostnames, and IPs referenced in request commands.
- **Trust Score Index**: Calculates an aggregate Trust Score from 0 to 100 based on 5 security dimensions:
  - **Code Safety**
  - **Supply Chain Safety**
  - **Secrets Hygiene**
  - **Network Risk**
  - **Container Security**
- **HTML Dashboards**: Generates a self-contained, responsive glassmorphic dark-mode report (`report.html`) complete with circular trust gauges and filterable findings.
- **JSON Integration Reports**: Outputs a machine-readable `report.json` with trust scores and categorized findings for CI/CD gates.

---

## 🚀 Installation & Setup

SkillGuard requires **Python 3.12+**.

1. Clone or download the repository.
2. Install dependencies:
   ```bash
   pip install -e .
   ```
   Or install requirements manually:
   ```bash
   pip install typer rich pydantic gitpython pytest
   ```

---

## 💻 CLI Usage

Scan a repository, directory, or individual file using:

```bash
skillguard scan <path> [OPTIONS]
```

### Options

* `--full`: Runs the complete suite including code AST scanners and all supply chain analyzers.
* `--html`: Generates an interactive, styled HTML dashboard report in `report.html`.
* `--json`: Generates a structured JSON summary report in `report.json` (or location specified by `--output`).
* `--ai`: Runs AI-powered Claim vs Behavior analysis to determine if a repository's capabilities align with its claimed purpose.
* `-o`, `--output <path>`: Specifies custom path for the generated JSON report (defaults to `report.json`).

### Examples

**Scan a python directory (AST scan only):**
```bash
skillguard scan ./my-mcp-server
```

**Run a full supply chain and secrets audit on a repository, outputting HTML and JSON reports:**
```bash
skillguard scan ./my-plugin-repo --full --html --json
```

**Scan a remote GitHub repository:**
```bash
skillguard scan https://github.com/modelcontextprotocol/servers
```

**Run a full scan on a remote GitHub repository with HTML and JSON reports:**
```bash
skillguard scan https://github.com/langchain-ai/langchain --full --html --json
```

**Run AI-powered Claim vs Behavior analysis on a local directory:**
```bash
skillguard scan ./my-mcp-server --ai
```

**Run AI-powered analysis on a remote GitHub repository:**
```bash
skillguard scan https://github.com/user/repo --ai
```

**Show the version of SkillGuard:**
```bash
skillguard version
```

---

## 🛡️ Trust Score & Deductions

Trust Scores start at 100 for each of the 5 categories. Deductions are subtracted based on the severity of the findings:

* 🔴 **CRITICAL** finding: **-25** points
* 🟠 **HIGH** finding: **-15** points
* 🟡 **MEDIUM** finding: **-10** points
* 🟢 **LOW** finding: **-5** points

The final overall **Trust Score** is the average of these 5 category scores. If the overall risk level is calculated as **HIGH** or **CRITICAL** (Trust Score < 50), the CLI exits with code `1` to serve as a CI/CD build failure gate.

---

## 📄 JSON Report Format

The scan produces a `report.json` containing the overall score, risk level, findings, and the detailed Trust Score breakdown:

```json
{
  "score": 65,
  "risk": "HIGH",
  "findings": [
    {
      "id": "SEC101",
      "severity": "CRITICAL",
      "category": "SECRET_ACCESS",
      "file": ".env",
      "line": 5,
      "message": "Hardcoded credential detected: OpenAI API Key"
    }
  ],
  "trust_score": {
    "overall_score": 75,
    "code_safety": 100,
    "supply_chain_safety": 100,
    "secrets_hygiene": 75,
    "network_risk": 100,
    "container_security": 100
  }
}
```

---

## 🛣️ Roadmap

### Phase 3: Advanced Behavioral Scans
- LLM semantic analysis of agent plugin manifests vs code declarations.
- Dynamic sandboxing and execution trace analysis of agent behaviors.

### Phase 4: Integrations & Directory
- SARIF format output support for GitHub Code Scanning actions.
- Centralized community trust score registry and badge integration.
