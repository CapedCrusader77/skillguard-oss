"""Safe benchmark runner for public MCP repositories.

Cloning is isolated to temporary directories and execution is delegated to the
fail-closed RuntimeCapture implementation. Results are JSON so a benchmark can
be rerun on a Linux CI runner without changing the scanner.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Iterable

from skillguard.analysis.claim_extractor import RuleBasedClaimExtractor
from skillguard.analysis.runtime_capture import RuntimeCapture
from skillguard.analysis.runtime_verification import verify_runtime
from skillguard.core.github_scanner import clone_repository, cleanup_repository


def run_runtime_benchmark(urls: Iterable[str], output_path: str = "benchmark_results.json", timeout_seconds: float = 10.0) -> Path:
    results: list[dict] = []
    for url in urls:
        url = url.strip()
        if not url or url.startswith("#"):
            continue
        result = {
            "url": url,
            "status": "not_run",
            "runtime_status": "not_run",
            "verification_available": False,
            "mismatch_types": [],
            "mismatch_count": 0,
        }
        temp_dir_obj = tempfile.TemporaryDirectory(prefix="skillguard_benchmark_")
        try:
            try:
                repo = clone_repository(url, temp_dir_obj.name)
                claims = RuleBasedClaimExtractor().extract_profile(repo)
                runtime = RuntimeCapture(timeout_seconds=timeout_seconds).capture(repo)
                verification = verify_runtime(claims, runtime)
                result.update({
                    "status": runtime.status,
                    "runtime_status": runtime.status,
                    "verification_available": verification.verification_available,
                    "claimed_purpose": claims.claimed_purpose,
                    "verification_score": verification.verification_score,
                    "trust_delta": verification.trust_delta,
                    "mismatch_count": len(verification.findings),
                    "mismatch_types": sorted({finding.mismatch_type for finding in verification.findings}),
                    "sample_findings": [f.model_dump() for f in verification.findings[:15]],
                    "runtime_error": runtime.error,
                })
            except Exception as exc:
                result.update({"status": "benchmark_error", "error": str(exc)})
        finally:
            try:
                cleanup_repository(temp_dir_obj.name)
            except Exception:
                pass
            temp_dir_obj.cleanup()
        results.append(result)

    output = Path(output_path).resolve()
    output.write_text(json.dumps({
        "schema_version": "1.0",
        "tool": "skillguard claim-vs-runtime verification",
        "timeout_seconds": timeout_seconds,
        "results": results,
        "summary": summarize_benchmark(results),
    }, indent=2), encoding="utf-8")
    return output


def summarize_benchmark(results: list[dict]) -> dict:
    completed = [result for result in results if result.get("status") == "completed"]
    mismatched = [result for result in completed if result.get("mismatch_count", 0) > 0]
    type_counts: dict[str, int] = {}
    for result in completed:
        for mismatch_type in result.get("mismatch_types", []):
            type_counts[mismatch_type] = type_counts.get(mismatch_type, 0) + 1
    return {
        "total": len(results),
        "completed": len(completed),
        "with_mismatch": len(mismatched),
        "mismatch_rate": round(len(mismatched) / len(completed), 4) if completed else None,
        "mismatch_types": dict(sorted(type_counts.items(), key=lambda item: (-item[1], item[0]))),
        "runtime_available": bool(completed),
        "note": "No runtime was executed; this artifact is not evidence of clean behavior." if not completed else None,
    }
