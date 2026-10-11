# RLogics Security Assessment: DevSecOps Implementation Guide

Platform: Windows, PowerShell. Workspace: `C:\Users\hp\Documents\rlogics-security-assessment`.
To get a Word file: open this document in Word (File > Open) and Save As `.docx`.

## 1. Purpose and overview

A small, local, end-to-end DevSecOps security path built around a **deliberately vulnerable Flask app**. It shows where security checks sit at each delivery stage (commit, pull request, build, registry, deploy), how each check returns a decision (PASS, WARN, BLOCK, REQUIRE EXCEPTION), and how audit evidence is produced. The app is scanned, the findings are fixed in a second copy (`remediation/`), and the scans are repeated to prove the fix.

Key concepts:

- **Finding**: a tool reports something may be wrong. Information only.
- **Gate**: a policy decision that a class of finding stops the pipeline.
- **Exception**: a recorded, approved, time-boxed acceptance of risk for a finding that would otherwise block.
- **SBOM**: Software Bill of Materials, the component inventory (CycloneDX or SPDX).
- **Signing**: a Cosign signature proving the artifact is the one the pipeline produced and is unaltered.

## 2. Pipeline stages

```
Commit -> Pull request -> Build -> Registry -> Pre-prod DAST -> Admission -> Deploy
secret    Semgrep +      image +   push by     ZAP baseline /   verify
scan      Trivy fs       Trivy +   digest +    Wapiti           signature
                         SBOM      Cosign sign                  + attestations
```

| Stage | Tool | What it checks | Output |
|---|---|---|---|
| SAST (PR) | Semgrep + custom rules | Injection, hard-coded secret, debug mode in source | `devsecops/sast/results` |
| Dependency / secret / IaC (PR) | Trivy fs | Vulnerable packages, secrets, Dockerfile misconfiguration | `devsecops/container-scan/results` |
| SBOM (build) | Trivy (CycloneDX), Syft (SPDX) | Component inventory | `devsecops/container-scan/results` |
| Image scan (build) | Trivy image | OS and package CVEs in the image | `devsecops/container-scan/results` |
| Sign / verify (registry) | Cosign | Valid signature accepted, tampered or unsigned rejected | `devsecops/signing/results` |
| DAST (pre-prod) | Wapiti (active), ZAP baseline (passive) | Runtime flaws on the running app | `devsecops/dast/results` |
| Gate decision | `run-local.ps1` | Applies the decision table | `devsecops/pipeline/gate-summary.txt` |

## 3. Repository layout

| Path | Purpose |
|---|---|
| `devsecops/app-or-lab-target/` | Vulnerable Flask app, old pinned `requirements.txt`, Dockerfile (python:3.8-slim, root) |
| `devsecops/remediation/` | Fixed versions of the same three files |
| `devsecops/sast/` | `semgrep-rules.yml` (4 custom rules) and results |
| `devsecops/container-scan/` | Trivy results and SBOMs |
| `devsecops/dast/` | `run-wapiti.ps1`, ZAP plans, results |
| `devsecops/signing/` | `sign-verify.ps1`, `cosign.pub`, results (`cosign.key` is git-ignored) |
| `devsecops/pipeline/` | `run-local.ps1`, `run-docker-stages.ps1`, `devsecops.yml`, `GATE-DECISION-TABLE.md`, `exceptions/` |
| `.venv`, `.venv-dast` | Virtual environments for Semgrep/app and for Wapiti (separate to avoid conflicts) |

## 4. The vulnerable application

| Weakness | Where | CWE / OWASP | Found by |
|---|---|---|---|
| SQL injection | `/user?name=` uses `%` string formatting | CWE-89 / A03 | Semgrep |
| OS command injection | `/ping?host=` uses `shell=True` | CWE-78 / A03 | Semgrep, Wapiti |
| Hard-coded secret | AWS-style key at top of `app.py` | CWE-798 / A07 | Semgrep, Trivy |
| Debug mode | `app.run(debug=True)` | CWE-489 / A05 | Semgrep |
| Vulnerable dependencies | flask 2.0.1, werkzeug 2.0.1, pyyaml 5.3.1 | Known CVEs | Trivy |
| Insecure Dockerfile | No `USER`, runs as root | DS-0002 | Trivy |
| Missing headers | No CSP, X-Frame-Options, X-Content-Type-Options | A05 | Wapiti, ZAP |

> Scan only this lab app on `127.0.0.1`. Active DAST sends real attack payloads and must only be run against systems you own and are authorised to test.

## 5. Prerequisites

| Tool | Version used | Purpose | Install |
|---|---|---|---|
| Python | 3.12 | Semgrep, Wapiti, the app | `winget install Python.Python.3.12` |
| Semgrep | 1.180 | SAST | pip in `.venv` |
| Wapiti 3 | 3.x | Active DAST | pip in `.venv-dast` |
| Trivy | 0.75 | Dependency, secret, IaC, image scan | `winget install AquaSecurity.Trivy` |
| Syft | 1.52 | SPDX SBOM | github.com/anchore/syft releases, or `scoop install syft` |
| Cosign | 3.1.3 | Sign and verify | github.com/sigstore/cosign releases; keep the file name `cosign-windows-amd64.exe` and put it on PATH |
| Docker Desktop | current | Image build, registry, ZAP container | `winget install Docker.DockerDesktop` |

Open a new PowerShell window after installing, then verify:

```powershell
python --version
trivy --version
syft version
cosign-windows-amd64 version
docker --version
```

> Docker was not found on PATH on this machine. Install and start Docker Desktop before Step 8.

## 6. One-time environment setup

```powershell
cd C:\Users\hp\Documents\rlogics-security-assessment
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# Semgrep + app environment (Flask is needed because run-wapiti.ps1 starts the app with this interpreter)
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install semgrep flask

# DAST environment
py -3.12 -m venv .venv-dast
.\.venv-dast\Scripts\python.exe -m pip install --upgrade pip
.\.venv-dast\Scripts\python.exe -m pip install wapiti3

# Confirm
.\.venv\Scripts\semgrep.exe --version
.\.venv-dast\Scripts\wapiti.exe --version
```

## 7. Step-by-step implementation

Run all commands from the project root. Steps 1 to 6 are the individual stages; Step 7 automates them.

### Step 1. Review and run the target

Read `devsecops/app-or-lab-target/app.py`, `requirements.txt` and `Dockerfile`, and identify the weaknesses in section 4.

```powershell
.\.venv\Scripts\python.exe devsecops\app-or-lab-target\app.py
# In a second terminal:
Invoke-WebRequest "http://127.0.0.1:5000/user?name=alice" -UseBasicParsing | Select-Object -Expand Content
Invoke-WebRequest "http://127.0.0.1:5000/user?name=x' OR '1'='1" -UseBasicParsing | Select-Object -Expand Content
# Ctrl+C in the first terminal to stop
```

The second request returns every row: the SQL injection working.

### Step 2. SAST with Semgrep

```powershell
New-Item -ItemType Directory -Force devsecops\sast\results | Out-Null
$env:PYTHONUTF8 = '1'
.\.venv\Scripts\semgrep.exe scan --config devsecops\sast\semgrep-rules.yml --metrics=off --disable-version-check --text  --output devsecops\sast\results\semgrep.txt   devsecops\app-or-lab-target
.\.venv\Scripts\semgrep.exe scan --config devsecops\sast\semgrep-rules.yml --metrics=off --disable-version-check --json  --output devsecops\sast\results\semgrep.json  devsecops\app-or-lab-target
.\.venv\Scripts\semgrep.exe scan --config devsecops\sast\semgrep-rules.yml --metrics=off --disable-version-check --sarif --output devsecops\sast\results\semgrep.sarif devsecops\app-or-lab-target
Get-Content devsecops\sast\results\semgrep.txt
```

Expected: 4 findings, 3 ERROR (SQL injection, command injection, hard-coded secret) and 1 WARNING (debug mode). SARIF is what GitHub code scanning uses for PR annotations. Add `--severity ERROR --error` to make Semgrep fail the build on ERROR findings.

### Step 3. Dependency, secret and IaC scan with Trivy

```powershell
New-Item -ItemType Directory -Force devsecops\container-scan\results | Out-Null
trivy fs --scanners vuln,secret,misconfig --format json --output devsecops\container-scan\results\trivy-fs.json devsecops\app-or-lab-target
trivy fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL --format table --output devsecops\container-scan\results\trivy-fs.txt devsecops\app-or-lab-target
Get-Content devsecops\container-scan\results\trivy-fs.txt
```

Expected: 4 vulnerable packages (PyYAML CRITICAL; Flask and Werkzeug HIGH), 1 secret, 2 Dockerfile misconfigurations. The first run downloads the vulnerability database and needs internet access.

### Step 4. Generate SBOMs

```powershell
trivy fs --format cyclonedx --output devsecops\container-scan\results\sbom.cdx.json devsecops\app-or-lab-target
syft dir:devsecops\app-or-lab-target -o spdx-json=devsecops\container-scan\results\sbom.spdx.json
```

In production the SBOM is generated from the built image and attached to the image digest as a signed attestation.

### Step 5. Sign and verify with Cosign

`sign-verify.ps1` creates a lab-only key pair on first run, signs the zip, verifies it, then appends one byte to a copy and confirms verification fails. Output: `devsecops/signing/results/cosign.txt`.

```powershell
New-Item -ItemType Directory -Force devsecops\signing\dist | Out-Null
Compress-Archive -Force -Path devsecops\app-or-lab-target\* -DestinationPath devsecops\signing\dist\lab-app.zip
.\devsecops\signing\sign-verify.ps1 -Artifact devsecops\signing\dist\lab-app.zip
Get-Content devsecops\signing\results\cosign.txt
```

Expected: original verify exit code 0; tampered verify exit code non-zero.

Manual equivalent:

```powershell
$env:COSIGN_PASSWORD = 'lab-only-password'
cosign-windows-amd64 generate-key-pair
cosign-windows-amd64 sign-blob --yes --key cosign.key --use-signing-config=false --tlog-upload=false --bundle lab-app.zip.bundle lab-app.zip
cosign-windows-amd64 verify-blob --key cosign.pub --bundle lab-app.zip.bundle --insecure-ignore-tlog lab-app.zip
```

### Step 6. DAST with Wapiti (active, localhost only)

`run-wapiti.ps1` starts the app on 127.0.0.1:5000, runs Wapiti (modules sql, exec, xss, http_headers, cookieflags, csp, backup, file), writes JSON and HTML reports, then stops the app.

```powershell
.\devsecops\dast\run-wapiti.ps1
Get-Content devsecops\dast\results\wapiti-summary.txt
```

Expected: command execution confirmed at runtime on `/ping`, plus missing CSP, clickjacking and MIME-type header findings. Wapiti does not detect the SQL injection because the endpoint returns no recognisable database error. Static and dynamic testing complement each other.

### Step 7. Run the whole local pipeline and read the gates

`run-local.ps1` runs Steps 2 to 6, evaluates each gate and writes `devsecops/pipeline/gate-summary.txt`.

```powershell
.\devsecops\pipeline\run-local.ps1             # report mode: prints gates, always continues
.\devsecops\pipeline\run-local.ps1 -SkipDast   # skip DAST
.\devsecops\pipeline\run-local.ps1 -Enforce    # exit code 1 on any BLOCK or REQUIRE EXCEPTION
Get-Content devsecops\pipeline\gate-summary.txt
```

| Gate | Outcome | Reason |
|---|---|---|
| SAST ERROR findings | BLOCK | 3 ERROR (injection, secret) |
| SAST WARNING findings | WARN | 1 WARNING (debug mode) |
| Secret leakage | BLOCK | 1 secret found by Trivy |
| CRITICAL CVE, fix available | BLOCK | 1 (PyYAML) |
| HIGH CVE, fix available | WARN | 3 (Flask, Werkzeug); BLOCK if internet-facing |
| IaC / Dockerfile policy | WARN | 2 misconfigurations (root) |
| SBOM present | PASS | CycloneDX and SPDX generated |
| Signature verification | PASS | Valid accepted, tampered rejected |

Report mode is the default because the target is intentionally vulnerable; `-Enforce` is what a real pipeline uses.

### Step 8. Image stages with Docker

`run-docker-stages.ps1` needs Docker Desktop running and the Cosign key from Step 5 (run Step 5 or 7 first). It:

1. Builds `lab-app:local` (vulnerable) and `lab-app:fixed` (remediated).
2. Scans both with Trivy and creates an SPDX SBOM of the vulnerable image with Syft.
3. Starts a local registry (`registry:2` on localhost:5001) and pushes both images.
4. Signs `lab-app:local` by digest, verifies it, and confirms the unsigned `lab-app-unsigned:fixed` is rejected.
5. Runs the OWASP ZAP baseline (passive) from the official container against the lab container on 127.0.0.1:5000.
6. Removes the lab containers.

```powershell
docker version
.\devsecops\pipeline\run-docker-stages.ps1
Get-Content devsecops\signing\results\cosign-image.txt
Get-Content devsecops\container-scan\results\trivy-image.txt
```

Underlying commands:

```powershell
docker build -t lab-app:local devsecops\app-or-lab-target
docker build -t lab-app:fixed devsecops\remediation
trivy image --severity HIGH,CRITICAL lab-app:local
syft lab-app:local -o spdx-json=devsecops\container-scan\results\sbom-image.spdx.json

docker run -d --name lab-registry -p 5001:5000 registry:2
docker tag lab-app:local localhost:5001/lab-app:local
docker push localhost:5001/lab-app:local
$digest = docker image inspect localhost:5001/lab-app:local --format '{{index .RepoDigests 0}}'
cosign-windows-amd64 sign --yes --key devsecops\signing\cosign.key --use-signing-config=false --tlog-upload=false $digest
cosign-windows-amd64 verify --key devsecops\signing\cosign.pub --insecure-ignore-tlog $digest

docker run -d --name lab-target -p 127.0.0.1:5000:5000 lab-app:local
docker run --rm -v "${PWD}\devsecops\dast\results:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:5000 -r zap-baseline.html -J zap-baseline.json -I
docker rm -f lab-target lab-registry
```

Expected: signed image verifies; unsigned image fails with "no signatures found"; ZAP shows about 7 WARN-NEW and 0 FAIL-NEW.

### Step 9. Remediate and prove the fix

```powershell
.\.venv\Scripts\semgrep.exe scan --config devsecops\sast\semgrep-rules.yml --metrics=off --disable-version-check --text --output devsecops\remediation\results\semgrep-after.txt devsecops\remediation
trivy fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL --format table --output devsecops\remediation\results\trivy-after.txt devsecops\remediation
Get-Content devsecops\remediation\results\semgrep-after.txt
Get-Content devsecops\remediation\results\trivy-after.txt
```

| Issue | Before | After |
|---|---|---|
| SQL injection | `"... WHERE name = '%s'" % name` | `execute("... WHERE name = ?", (name,))` |
| Command injection | `check_output("ping -n 1 " + host, shell=True)` | Validate with `ipaddress.ip_address()`, then `check_output(["ping", "-n", "1", host])` |
| Hard-coded secret | Literal in source | Read from environment |
| Debug mode | `debug=True` | Off |
| Dependencies | flask 2.0.1, werkzeug 2.0.1, pyyaml 5.3.1 | flask 3.1.3, werkzeug 3.1.9, pyyaml 6.0.2 |
| Dockerfile | python:3.8-slim, root | python:3.12-slim, non-root `appuser` |

Expected: Semgrep 0 findings; Trivy fs 0 vulnerabilities and 0 misconfigurations. The fixed image still has about 44 HIGH findings from the Debian base layer; these need a base-image refresh or distroless base and are handled under the remediation SLA.

### Step 10. Gate decision table and exceptions

`devsecops/pipeline/GATE-DECISION-TABLE.md` defines the policy:

- **BLOCK**: secrets, signature failures, fixable CRITICAL CVEs, request-reachable injection, missing SBOM, CISA-KEV vulnerabilities.
- **WARN** (with SLA and owner): fixable HIGH on internal services, MEDIUM/LOW, misconfiguration outside production.
- **REQUIRE EXCEPTION**: CRITICAL with no fix.

An exception is data in `devsecops/pipeline/exceptions/EXC-0001.example.yaml`: finding, justification, compensating controls, owner, approver, ticket, creation date, expiry (max 30 days for CRITICAL). An expired exception reverts to BLOCK. False positives are suppressed on the line only, with a reason, reviewed in the PR:

```python
query = build_query(name)  # nosemgrep: lab.python.sql-string-formatting -- name validated by allow-list
```

### Step 11. Continuous integration (GitHub Actions)

`devsecops/pipeline/devsecops.yml` is copied to `.github/workflows/devsecops.yml`.

- **pr-checks** (every PR): Semgrep and Trivy filesystem scans with SARIF upload. Findings are reported but do not fail the job in this report-only workflow.
- **build-sign-dast** (push to main or master, after pr-checks): build, Trivy image scan (report-only), Syft SBOM, ZAP baseline, keyless Cosign signing and SBOM attestation (when a registry is configured), evidence bundle kept 90 days.

The workflow also runs on pushes to `master`, the current local branch. Branch protection can require `pr-checks` for merge hygiene; this report-only version does not block on the lab's planted findings.

```powershell
git add .
git commit -m "DevSecOps pipeline"
git push origin main
```

> Commit only `cosign.pub`. `cosign.key` stays out of Git (already in `.gitignore`).

## 8. Summary of results

| Area | Tool | Result |
|---|---|---|
| SAST | Semgrep | 4 findings (3 ERROR, 1 WARNING) before; 0 after |
| Dependencies / secrets / IaC | Trivy fs | 4 vulnerabilities (1 CRITICAL, 3 HIGH), 1 secret, 2 misconfigurations before; 0 after |
| Image scan | Trivy image | 119 HIGH/CRITICAL on `lab-app:local`; 44 HIGH remain on the fixed image (base layer) |
| SBOM | Trivy, Syft | CycloneDX and SPDX for source and image |
| Signing | Cosign | Valid accepted; tampered blob and unsigned image rejected |
| DAST active | Wapiti | Command execution confirmed; CSP, clickjacking, MIME header findings |
| DAST passive | ZAP baseline | 0 FAIL, 7 WARN, 60 PASS |

## 9. Lab versus production

- Signing is keyless in CI: the pipeline's OIDC identity gets a short-lived Fulcio certificate and the signature is logged in Rekor. No long-lived key to steal.
- SBOM, scan results and build provenance are attached to the image digest as attestations.
- A Kubernetes admission controller (Kyverno or Sigstore policy-controller) verifies signature, signing identity and attestations on every deploy and rejects anything else.
- Evidence (PR approvals, scan results, SBOM, digest, signatures, DAST report, policy version, exceptions, admission logs) is kept in write-once storage, commonly 12 months or more.
- Example SLAs: CRITICAL or known-exploited in 7 days, HIGH in 14 to 30 days, MEDIUM in 90 days.

## 10. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Script cannot be loaded | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force` in the same terminal |
| `trivy`, `syft` or `docker` not recognised | Not installed or PATH stale; open a new terminal |
| `cosign-windows-amd64` not recognised | Scripts call this exact name; rename the binary and add to PATH |
| Semgrep Unicode errors | `$env:PYTHONUTF8 = '1'` |
| Wapiti: lab app did not start | Flask missing in `.venv`, or port 5000 in use |
| Trivy first run slow or failing | It downloads its database; check internet or proxy |
| `run-docker-stages.ps1` fails at sign | `cosign.key` missing; run `sign-verify.ps1` or `run-local.ps1` first |
| ZAP installer blocked by Defender | Use the official ZAP container (Step 8) |
| Port 5000 or 5001 already allocated | `docker rm -f lab-registry lab-target`, re-run |

## 11. Command quick reference

```powershell
cd C:\Users\hp\Documents\rlogics-security-assessment
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# One-time setup
py -3.12 -m venv .venv ; .\.venv\Scripts\python.exe -m pip install semgrep flask
py -3.12 -m venv .venv-dast ; .\.venv-dast\Scripts\python.exe -m pip install wapiti3

# Full local pipeline
.\devsecops\pipeline\run-local.ps1
.\devsecops\pipeline\run-local.ps1 -Enforce
.\devsecops\pipeline\run-local.ps1 -SkipDast

# Image stages (Docker Desktop running)
.\devsecops\pipeline\run-docker-stages.ps1

# Review outputs
Get-Content devsecops\pipeline\gate-summary.txt
Get-Content devsecops\sast\results\semgrep.txt
Get-Content devsecops\container-scan\results\trivy-fs.txt
Get-Content devsecops\signing\results\cosign.txt
Get-Content devsecops\dast\results\wapiti-summary.txt
```
