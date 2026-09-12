"""Claim-vs-runtime comparison and weighted mismatch findings."""

from __future__ import annotations

import fnmatch
from pathlib import Path

from pydantic import BaseModel, Field

from skillguard.analysis.models import AccessMode, ClaimProfile, ClaimState, ResourceClaim
from skillguard.analysis.runtime_capture import RuntimeFileAccess, RuntimeNetworkAccess, RuntimeProfile


class MismatchFinding(BaseModel):
    id: str
    mismatch_type: str
    severity: str
    weight: int
    message: str
    expected: list[str] = Field(default_factory=list)
    observed: list[str] = Field(default_factory=list)


class RuntimeVerificationReport(BaseModel):
    claim_profile: ClaimProfile
    runtime_profile: RuntimeProfile
    findings: list[MismatchFinding] = Field(default_factory=list)
    verification_available: bool = False
    trust_delta: int | None = None
    verification_score: int | None = Field(None, ge=0, le=100)
    verdict: str = "Runtime verification unavailable"


WEIGHTS = {
    "unexpected_sensitive_read": 35,
    "unexpected_write": 40,
    "unexpected_read": 12,
    "unexpected_network": 25,
    "unexpected_subprocess": 30,
    "unexpected_system_resource": 35,
    "unknown_claim": 5,
    "conflicting_claim": 10,
    "execution_incomplete": 20,
}


def verify_runtime(claims: ClaimProfile, runtime: RuntimeProfile) -> RuntimeVerificationReport:
    findings: list[MismatchFinding] = []
    _add_claim_state_findings(claims, runtime, findings)
    for access in runtime.files_touched:
        for mode in access.modes:
            if mode == "write":
                _compare_file(claims.filesystem, access, mode, findings)
            else:
                _compare_file(claims.filesystem, access, "read", findings)
    for connection in runtime.network_connections:
        _compare_network(claims.network, connection, findings)
    if runtime.subprocesses and not _allows(claims.subprocess, AccessMode.EXECUTE):
        for process in runtime.subprocesses:
            _append(findings, "VER-SUBPROCESS", "unexpected_subprocess", "HIGH", WEIGHTS["unexpected_subprocess"],
                    f"Spawned unexpected subprocess: {process.executable}", observed=[process.executable])
    for resource in runtime.system_resources:
        if not _allows(claims.system_resources, AccessMode.ACCESS):
            weight = WEIGHTS["unexpected_system_resource"] if _sensitive(resource) else WEIGHTS["unexpected_read"]
            _append(findings, "VER-SYSTEM", "unexpected_system_resource", "HIGH" if weight > 20 else "MEDIUM", weight,
                    f"Accessed unexpected system resource: {resource}", observed=[resource])

    if runtime.status in {"timeout", "crashed", "could_not_execute", "sandbox_unavailable", "invalid_target"}:
        weight = WEIGHTS["execution_incomplete"] if runtime.status != "sandbox_unavailable" else 0
        severity = "HIGH" if runtime.status in {"timeout", "crashed"} else "MEDIUM"
        _append(findings, "VER-EXECUTION", "execution_incomplete", severity, weight,
                f"Runtime verification status: {runtime.status}. {runtime.error or ''}".strip())

    if runtime.status != "completed":
        return RuntimeVerificationReport(
            claim_profile=claims,
            runtime_profile=runtime,
            findings=findings,
            verification_available=False,
            trust_delta=None,
            verification_score=None,
            verdict="Runtime verification unavailable or incomplete",
        )

    total = sum(f.weight for f in findings)
    # Keep the raw delta for comparison and auditability even when the
    # user-facing score bottoms out at zero.
    delta = -total
    score = max(0, 100 + delta)
    verdict = "Behavior matches declared claims" if not findings else (
        "Behavior materially exceeds declared claims" if score < 60 else "Behavior partially exceeds declared claims"
    )
    return RuntimeVerificationReport(claim_profile=claims, runtime_profile=runtime, findings=findings,
                                     verification_available=True, trust_delta=delta,
                                     verification_score=score, verdict=verdict)


def _compare_file(claim: ResourceClaim, access: RuntimeFileAccess, mode: str, findings: list[MismatchFinding]) -> None:
    if claim.state == ClaimState.CONFLICTING:
        return
    if claim.state == ClaimState.UNKNOWN:
        _append(findings, "VER-CLAIM-UNKNOWN", "unknown_claim", "MEDIUM", WEIGHTS["unknown_claim"],
                f"Observed filesystem {mode} access while the claim is ambiguous", observed=[access.path])
        return
    if not _allows(claim, AccessMode.WRITE if mode == "write" else AccessMode.READ):
        kind = "unexpected_sensitive_read" if mode == "read" and _sensitive(access.path) else ("unexpected_write" if mode == "write" else "unexpected_read")
        severity = "CRITICAL" if kind == "unexpected_sensitive_read" else ("HIGH" if mode == "write" else "MEDIUM")
        _append(findings, "VER-FILE", kind, severity, WEIGHTS[kind], f"Observed unexpected filesystem {mode}: {access.path}", observed=[access.path])
    elif claim.resources and not _matches_resource(access.path, claim.resources):
        kind = "unexpected_write" if mode == "write" else "unexpected_read"
        _append(findings, "VER-FILE-SCOPE", kind, "HIGH" if mode == "write" else "MEDIUM", WEIGHTS[kind],
                f"Observed filesystem {mode} outside claimed scope: {access.path}", expected=claim.resources, observed=[access.path])


def _compare_network(claim: ResourceClaim, connection: RuntimeNetworkAccess, findings: list[MismatchFinding]) -> None:
    if claim.state == ClaimState.UNKNOWN:
        _append(findings, "VER-CLAIM-UNKNOWN", "unknown_claim", "MEDIUM", WEIGHTS["unknown_claim"],
                "Observed network access while the network claim is ambiguous", observed=[connection.address])
        return
    if not _allows(claim, AccessMode.CONNECT if connection.operation == "connect" else AccessMode.LISTEN):
        _append(findings, "VER-NETWORK", "unexpected_network", "HIGH", WEIGHTS["unexpected_network"],
                f"Observed unexpected network {connection.operation} to {connection.address}:{connection.port or ''}", observed=[connection.address])
    elif claim.resources and not any(_matches_resource(connection.address, [resource]) for resource in claim.resources):
        _append(findings, "VER-NETWORK-SCOPE", "unexpected_network", "HIGH", WEIGHTS["unexpected_network"],
                f"Observed network endpoint outside claimed scope: {connection.address}", expected=claim.resources, observed=[connection.address])


def _add_claim_state_findings(claims: ClaimProfile, runtime: RuntimeProfile, findings: list[MismatchFinding]) -> None:
    for name, claim in (("filesystem", claims.filesystem), ("network", claims.network), ("subprocess", claims.subprocess), ("system resources", claims.system_resources)):
        if claim.state == ClaimState.CONFLICTING:
            _append(findings, "VER-CLAIM-CONFLICT", "conflicting_claim", "MEDIUM", WEIGHTS["conflicting_claim"],
                    f"Conflicting {name} claims were found; evidence was preserved rather than resolved")


def _allows(claim: ResourceClaim, mode: AccessMode) -> bool:
    return claim.state in {ClaimState.DECLARED, ClaimState.UNRESTRICTED} and (claim.state == ClaimState.UNRESTRICTED or mode in claim.modes)


def _matches_resource(value: str, patterns: list[str]) -> bool:
    normalized = value.replace("\\", "/")
    return any(fnmatch.fnmatch(normalized, pattern.replace("\\", "/")) or fnmatch.fnmatch(normalized, f"*{pattern}") for pattern in patterns)


def _sensitive(path: str) -> bool:
    lower = path.lower().replace("\\", "/")
    return any(token in lower for token in ("/.ssh", "/.aws", "/.config", "/.env", "id_rsa", "passwd", "shadow", "secret", "token"))


def _append(findings: list[MismatchFinding], id_: str, kind: str, severity: str, weight: int, message: str, *, expected: list[str] | None = None, observed: list[str] | None = None) -> None:
    findings.append(MismatchFinding(id=id_, mismatch_type=kind, severity=severity, weight=weight, message=message,
                                    expected=expected or [], observed=observed or []))
