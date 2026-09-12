# Claim-vs-Runtime Scoring

Runtime verification starts at 100 and applies a negative trust delta for
each discrete finding. The score is clamped to 0. Findings are retained
individually so users can see whether a deduction came from a sensitive file,
an endpoint, a subprocess, or incomplete execution.

| Finding | Weight | Rationale |
| --- | ---: | --- |
| Unexpected sensitive read | 35 | Credential stores and system identity files are high-value targets even when no write occurs. |
| Unexpected write | 40 | A write can alter user data, persistence, or configuration and is more consequential than a read. |
| Unexpected ordinary read | 12 | A bounded read is concerning but usually less damaging than mutation or credential access. |
| Unexpected network endpoint | 25 | An unclaimed connection can disclose data and is observable evidence of an undeclared capability. |
| Unexpected subprocess | 30 | Process creation expands the attack surface and can chain into arbitrary command execution. |
| Unexpected system resource | 35 | Access to `/proc`, devices, credential locations, or protected system files is high risk. |
| Ambiguous claim | 5 | The claim cannot safely authorize or reject the event; the small deduction signals uncertainty without calling it malicious. |
| Conflicting claim | 10 | Contradictory documentation reduces confidence in the declared contract and needs review. |
| Incomplete execution | 20 | A crash or timeout means the observed run is not a pass. It is not scored as a capability mismatch by itself. |

Weights are intentionally additive. The displayed score is clamped at zero,
but the raw negative trust delta remains unbounded so additional evidence is
not hidden when a run already reaches the floor. A sandbox-unavailable result receives a visible
status finding with zero mismatch weight, but it also has
`verification_available: false`, `verification_score: null`, and
`trust_delta: null`; it is never eligible for a clean-runtime score or a
benchmark denominator.

The v1 score is evidence from one bounded invocation, not a proof of absence.
Multiple representative inputs and behavioral baselines are future work.
