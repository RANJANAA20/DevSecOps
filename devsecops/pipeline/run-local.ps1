# Local DevSecOps pipeline. Stages mirror the GitHub Actions workflow.
# Default is report mode (the lab target is intentionally vulnerable); -Enforce exits non-zero on any BLOCK.
param(
    [switch]$Enforce,
    [switch]$SkipDast,
    [switch]$ActiveDast,
    [string]$Target = "$PSScriptRoot\..\app-or-lab-target"
)

$ErrorActionPreference = 'Continue'
$env:PYTHONUTF8 = '1'
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$Target = (Resolve-Path $Target).Path
$ds = "$root\devsecops"
$semgrep = "$root\.venv\Scripts\semgrep.exe"
$gates = [ordered]@{}

function Stage($n) { Write-Host "`n=== $n" -ForegroundColor Cyan }
function Gate($name, $outcome, $why) {
    $script:gates[$name] = [pscustomobject]@{ Gate = $name; Outcome = $outcome; Reason = $why }
}

# Stage 1: SAST (commit / PR)
Stage 'SAST: Semgrep'
$sast = "$ds\sast\results"; New-Item -ItemType Directory -Force $sast | Out-Null
& $semgrep scan --config "$ds\sast\semgrep-rules.yml" --metrics=off --disable-version-check --quiet --json --output "$sast\semgrep.json" $Target 2>&1 | Out-Null
& $semgrep scan --config "$ds\sast\semgrep-rules.yml" --metrics=off --disable-version-check --quiet --sarif --output "$sast\semgrep.sarif" $Target 2>&1 | Out-Null
& $semgrep scan --config "$ds\sast\semgrep-rules.yml" --metrics=off --disable-version-check --quiet --text --output "$sast\semgrep.txt" $Target 2>&1 | Out-Null
$sg = Get-Content "$sast\semgrep.json" -Raw | ConvertFrom-Json
$sgErr = @($sg.results | Where-Object { $_.extra.severity -eq 'ERROR' }).Count
$sgWarn = @($sg.results | Where-Object { $_.extra.severity -eq 'WARNING' }).Count
Gate 'SAST ERROR findings' $(if ($sgErr) { 'BLOCK' } else { 'PASS' }) "$sgErr ERROR (injection/secret)"
Gate 'SAST WARNING findings' $(if ($sgWarn) { 'WARN' } else { 'PASS' }) "$sgWarn WARNING (misconfiguration)"

# Stage 2: dependency, secret, IaC scan (PR / build)
Stage 'Scan: Trivy filesystem'
$cs = "$ds\container-scan\results"; New-Item -ItemType Directory -Force $cs | Out-Null
trivy fs --quiet --scanners vuln,secret,misconfig --format json --output "$cs\trivy-fs.json" $Target
trivy fs --quiet --scanners vuln,secret,misconfig --severity HIGH,CRITICAL --format table --output "$cs\trivy-fs.txt" $Target
$tv = Get-Content "$cs\trivy-fs.json" -Raw | ConvertFrom-Json
$vulns = @($tv.Results | ForEach-Object { $_.Vulnerabilities } | Where-Object { $_ })
$secrets = @($tv.Results | ForEach-Object { $_.Secrets } | Where-Object { $_ })
$miscfg = @($tv.Results | ForEach-Object { $_.Misconfigurations } | Where-Object { $_ })
$critFix = @($vulns | Where-Object { $_.Severity -eq 'CRITICAL' -and $_.FixedVersion }).Count
$critNoFix = @($vulns | Where-Object { $_.Severity -eq 'CRITICAL' -and -not $_.FixedVersion }).Count
$highFix = @($vulns | Where-Object { $_.Severity -eq 'HIGH' -and $_.FixedVersion }).Count
Gate 'Secret leakage' $(if ($secrets.Count) { 'BLOCK' } else { 'PASS' }) "$($secrets.Count) secret(s) found"
Gate 'CRITICAL CVE, fix available' $(if ($critFix) { 'BLOCK' } else { 'PASS' }) "$critFix found"
Gate 'CRITICAL CVE, no fix' $(if ($critNoFix) { 'REQUIRE EXCEPTION' } else { 'PASS' }) "$critNoFix found"
Gate 'HIGH CVE, fix available' $(if ($highFix) { 'WARN' } else { 'PASS' }) "$highFix found (BLOCK if internet-facing; lab is local)"
Gate 'IaC / Dockerfile policy' $(if ($miscfg.Count) { 'WARN' } else { 'PASS' }) "$($miscfg.Count) misconfiguration(s) (BLOCK in prod namespaces)"

# Stage 3: SBOM (build)
Stage 'SBOM: Trivy CycloneDX + Syft SPDX'
trivy fs --quiet --format cyclonedx --output "$cs\sbom.cdx.json" $Target
syft "dir:$Target" -q -o "spdx-json=$cs\sbom.spdx.json" 2>&1 | Out-Null
Gate 'SBOM present' $(if ((Test-Path "$cs\sbom.cdx.json") -and (Test-Path "$cs\sbom.spdx.json")) { 'PASS' } else { 'BLOCK' }) 'CycloneDX and SPDX generated'

# Stage 4: artifact, sign, verify (registry / deploy)
Stage 'Sign and verify: Cosign'
$dist = "$ds\signing\dist"; New-Item -ItemType Directory -Force $dist | Out-Null
Compress-Archive -Force -Path "$Target\*" -DestinationPath "$dist\lab-app.zip"
& "$ds\signing\sign-verify.ps1" -Artifact "$dist\lab-app.zip" | Out-Null
Gate 'Signature verification' $(if ($LASTEXITCODE -eq 0) { 'PASS' } else { 'BLOCK' }) 'valid signature accepted, tampered artifact rejected'

# Stage 5: DAST (pre-prod). Local, authorised target only.
if (-not $SkipDast) {
    Stage 'DAST: Wapiti (local, authorised target only)'
    $s = & "$ds\dast\run-wapiti.ps1" -Target $Target
    Gate 'DAST HIGH findings' $(if ($s.High) { 'BLOCK' } else { 'PASS' }) "$($s.High) injection-class finding(s)"
    Gate 'DAST MEDIUM/LOW findings' $(if ($s.Other) { 'WARN' } else { 'PASS' }) "$($s.Other) other finding(s)"
}

# Summary
Stage 'Gate summary'
$gates.Values | Format-Table Gate, Outcome, Reason -AutoSize | Out-String -Width 200 | Tee-Object "$ds\pipeline\gate-summary.txt"
$blocks = @($gates.Values | Where-Object { $_.Outcome -in 'BLOCK', 'REQUIRE EXCEPTION' }).Count
if ($Enforce -and $blocks) { Write-Host "FAILED: $blocks blocking gate(s)" -ForegroundColor Red; exit 1 }
Write-Host "Report mode: $blocks blocking gate(s) would stop this pipeline under -Enforce." -ForegroundColor Yellow
