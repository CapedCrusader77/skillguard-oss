# Claim-vs-Runtime Benchmark

The v1 benchmark input is [benchmark_mcp_servers.txt](benchmark_mcp_servers.txt).
It contains 20 public MCP-related repositories from the official
Model Context Protocol organization and widely used community servers.

Run it on a Linux host with `bubblewrap`, `strace`, Git, and Python 3.12+:

```bash
sudo apt-get install bubblewrap strace git
pip install -e .
skillguard benchmark-runtime benchmark_mcp_servers.txt --output benchmark_results.json
```

The command shallow-clones each repository into a temporary directory, extracts
claims, selects a Python entrypoint when one exists, executes only inside the
fail-closed sandbox, and writes structured status/results for every URL. A
repository that cannot be cloned, has no Python entrypoint, times out, crashes,
or runs on a host without the sandbox tools is recorded as a non-pass status.

## Interpretation

Only `completed` runs are included in the mismatch-rate denominator. The report
also preserves incomplete runs so unavailable execution is not confused with a
clean result. `mismatch_types` are counted once per repository, while the
underlying verification report retains each discrete finding.

## Responsible disclosure

This benchmark is intended for defensive testing of public code in an isolated
environment. Do not publish a specific serious finding until the maintainer has
been contacted privately and given reasonable time to investigate and remediate.
The benchmark runner does not submit issues, contact maintainers, or publish
findings automatically.

## Recorded run

The checked-in [benchmark_results.json](benchmark_results.json) reflects the real sandbox-verified run executed on an Ubuntu Linux CI runner with bubblewrap namespace isolation and strace syscall capture:

- **Total repositories attempted:** 20
- **Verification environment:** Linux `bubblewrap` + `strace` sandbox with unprivileged user isolation (`nobody` / uid 65534) and automated stdio MCP JSON-RPC initialize handshake.
- **Runtime verification available:** `true`
- **Completed runs:** 1 ([`modelcontextprotocol/quickstart-resources`](https://github.com/modelcontextprotocol/quickstart-resources) — `weather-server-python/weather.py`)
- **Repos with claim/behavior mismatch:** 0 (`mismatch_rate: 0.0%`)
- **Breakdown of runtime statuses across 20 repositories:**
  - `completed` (1 repo):
    - `modelcontextprotocol/quickstart-resources` (`weather-server-python/weather.py`): Validated clean (0 mismatches, trust delta: 0, verification score: 100). The server correctly initialized its tools via MCP JSON-RPC protocol over stdio and performed no unauthorized file operations.
  - `dependency_missing` (5 repos):
    - `modelcontextprotocol/servers` (missing `markdownify`)
    - `openapi/mcp-server` (missing `fastapi`)
    - `Bandwidth/mcp-server` (missing `fastmcp`)
    - `googleapis/genai-toolbox` (missing `toolbox_server`)
    - `awslabs/mcp` (missing dependencies)
    Each was halted fail-closed with 1 explicit diagnostic finding, preserving codebase auditability without emitting spurious false-positive claim mismatches.
  - `could_not_execute` (12 repos):
    - TypeScript, JavaScript, and Go implementations (e.g. `modelcontextprotocol/typescript-sdk`, `microsoft/playwright-mcp`, `github/github-mcp-server`, `browserbase/mcp-server-browserbase`, `firecrawl/firecrawl-mcp-server`, `exa-labs/exa-mcp-server`, etc.). Recorded fail-closed as non-Python entrypoints pending polyglot runtime sandbox support.
  - `timeout` (1 repo):
    - `modelcontextprotocol/python-sdk`: An SDK library rather than an interactive MCP server.
  - `benchmark_error` (1 repo):
    - `docker/mcp-servers`: Repository clone unavailable.

## Responsible disclosure

No exploitable vulnerabilities were identified in the verified servers. The verified benchmark runner strictly enforces that any candidate project exhibiting material claim/behavior discrepancies is flagged for review before public disclosure.
