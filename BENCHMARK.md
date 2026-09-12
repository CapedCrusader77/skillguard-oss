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

The checked-in [benchmark_results.json](benchmark_results.json) contains the
safe run performed from this Windows workspace: 20 repositories were attempted,
19 cloned successfully, and 1 could not be cloned. None of the 19 cloned
repositories was executed because Linux sandbox support was unavailable, so the
completed-run mismatch rate is **not applicable** rather than zero. For example,
`modelcontextprotocol/servers`, `microsoft/playwright-mcp`, and
`firecrawl/firecrawl-mcp-server` are recorded as `sandbox_unavailable`; these
are execution-status examples, not vulnerability findings.

## Current workspace note

The development workspace is Windows-based and does not provide Linux
`bubblewrap`/`strace`, so an external benchmark run is not claimed here. The
regression suite includes parser/scoring coverage and a Linux-only integration
test; CI runs the latter on Ubuntu.
