# Gate decision table

One policy, three outcomes. **BLOCK** stops the merge or deploy. **WARN** is visible to the developer but does not stop the pipeline; it is tracked against an SLA. **REQUIRE EXCEPTION** stops the pipeline until a named owner records a time-boxed, approved risk acceptance (see `exceptions/`).

| # | Signal | Condition | Outcome | Reasoning |
|---|---|---|---|---|
| 1 | Secret leakage | Any verified or high-confidence secret in source or image layers | **BLOCK** | Exposure is immediate and irreversible; the fix is rotation, not a code change. No exception route: rotate, then re-scan. |
| 2 | Secret leakage | Test or example credential (allow-listed by path and fingerprint) | **WARN** | Avoids teaching developers to ignore the gate. The allow-list entry is reviewed in PR. |
| 3 | Signature failure | Artifact unsigned, signature invalid, or signed by an unexpected identity | **BLOCK** (deploy) | Provenance is binary. Admission control must reject; there is no safe partial state. |
| 4 | Policy violation | Runs as root, privileged container, `latest` tag, debug mode on, missing resource limits | **BLOCK** in production namespaces, **WARN** elsewhere | Cheap to fix and high blast radius in prod. Dev and lab tolerate drift. |
| 5 | Dependency CVE | CRITICAL, fix available, package reachable at runtime | **BLOCK** | Fix is a version bump with a known cost. Waiting buys nothing. |
| 6 | Dependency CVE | CRITICAL, **no fix** available | **REQUIRE EXCEPTION** | The developer cannot remediate. Needs compensating control (WAF rule, feature flag, isolation) and an expiry date. |
| 7 | Dependency CVE | HIGH, fix available, service internet-facing | **BLOCK** | Exposure raises likelihood. Exploit code is often public within days. |
| 8 | Dependency CVE | HIGH, fix available, internal only | **WARN** with 14-day SLA | Reduced exposure. Auto-opened ticket. Escalates to BLOCK after SLA. |
| 9 | Dependency CVE | In CISA KEV or EPSS above 0.5, any severity | **BLOCK** | Known exploitation outranks CVSS. |
| 10 | Dependency CVE | MEDIUM or LOW | **WARN** | Batched into routine upgrades. Blocking here creates noise and a blocker culture. |
| 11 | SAST | ERROR-level injection (SQLi, command injection) on a request-reachable path | **BLOCK** | Directly exploitable, cheap to fix in the diff that introduced it. |
| 12 | SAST | WARNING-level misconfiguration | **WARN** | Surfaced as PR annotation; reviewer decides. |
| 13 | SAST | Finding marked false positive | **WARN** (suppressed) | Allowed only with an inline `nosemgrep` that names the rule and a reason. Reviewed in PR. |
| 14 | DAST | Confirmed HIGH alert from baseline scan on an internet-facing target | **BLOCK** (promotion to prod) | Runtime confirmation raises confidence above static findings. |
| 15 | DAST | MEDIUM or informational alert (missing headers, cookies) | **WARN** | Tracked as hardening backlog. |
| 16 | SBOM | SBOM missing or not attached to the artifact | **BLOCK** (release) | Without it, incident response cannot answer "are we affected?". |
| 17 | Exception | Past its expiry date | Reverts to original outcome (**BLOCK**) | Exceptions must decay. Nothing is accepted forever. |

## Principles behind the thresholds

1. **Block only what the developer can fix and the attacker can use.** Findings with no fix, no reachable path or no exposure become WARN or EXCEPTION, not a wall.
2. **Exposure and exploitability outrank raw severity.** An internet-facing HIGH with public exploit code is worse than an internal CRITICAL with no exploit path.
3. **Stricter as the artifact moves toward production.** PR checks mostly WARN; promotion to prod gates on signature, SBOM and confirmed runtime findings.
4. **Every WARN has an owner and a clock.** A warning with no SLA is a block that never gets enforced.
5. **Exceptions are data, not conversations.** Owner, justification, compensating control, expiry, approver, ticket link.

## Lab behaviour

The lab target is intentionally vulnerable, so `pipeline/run-local.ps1` runs in **report mode** by default: it evaluates each gate, prints the outcome, and continues. Use `-Enforce` to fail with a non-zero exit code on any BLOCK.
