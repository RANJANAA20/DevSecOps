# Image-level stages: build -> Trivy image scan -> Syft SBOM -> local registry -> Cosign sign/verify by digest -> ZAP baseline.
# Needs a working Docker engine. Local key and no transparency log stand in for keyless signing in CI.
$ErrorActionPreference = 'Continue'
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$ds = "$root\devsecops"
$cs = "$ds\container-scan\results"
$sig = "$ds\signing\results"
$dast = "$ds\dast\results"
$reg = 'localhost:5001'
$env:COSIGN_PASSWORD = 'lab-only-password'
$cosign = 'cosign-windows-amd64'
New-Item -ItemType Directory -Force $cs, $sig, $dast, "$ds\remediation\results" | Out-Null

Write-Host '== build'
docker build -q -t lab-app:local "$ds\app-or-lab-target" 2>&1 | Out-Null
docker build -q -t lab-app:fixed "$ds\remediation" 2>&1 | Out-Null

Write-Host '== Trivy image + Syft SBOM'
trivy image --quiet --format json --output "$cs\trivy-image.json" lab-app:local
trivy image --quiet --severity 'HIGH,CRITICAL' --format table --output "$cs\trivy-image.txt" lab-app:local
trivy image --quiet --severity 'HIGH,CRITICAL' --format table --output "$ds\remediation\results\trivy-image-after.txt" lab-app:fixed
syft lab-app:local -q -o "spdx-json=$cs\sbom-image.spdx.json" 2>$null

Write-Host '== registry, push, sign, verify'
docker rm -f lab-registry 2>&1 | Out-Null
docker run -d --name lab-registry -p 5001:5000 registry:2 2>&1 | Out-Null
docker tag lab-app:local "$reg/lab-app:local"
docker tag lab-app:fixed "$reg/lab-app-unsigned:fixed"
docker push "$reg/lab-app:local" 2>&1 | Out-Null
docker push "$reg/lab-app-unsigned:fixed" 2>&1 | Out-Null
$digest = (docker image inspect "$reg/lab-app:local" --format '{{range .RepoDigests}}{{println .}}{{end}}' | Where-Object { $_ -like "$reg/*" } | Select-Object -First 1).Trim()

$log = @("image: $digest", '== sign (by digest)')
$log += & $cosign sign --yes --key "$ds\signing\cosign.key" --use-signing-config=false --tlog-upload=false $digest 2>&1 | ForEach-Object { "$_" }
$log += '== verify signed image'
$log += & $cosign verify --key "$ds\signing\cosign.pub" --insecure-ignore-tlog $digest 2>&1 | ForEach-Object { "$_" }
$log += "verify exit=$LASTEXITCODE"
$log += '== verify unsigned image (expected to FAIL)'
$log += & $cosign verify --key "$ds\signing\cosign.pub" --insecure-ignore-tlog "$reg/lab-app-unsigned:fixed" 2>&1 | ForEach-Object { "$_" }
$log += "unsigned verify exit=$LASTEXITCODE (non-zero = admission would reject)"
$log | Set-Content "$sig\cosign-image.txt" -Encoding utf8

Write-Host '== ZAP baseline (passive) against the local container only'
docker rm -f lab-target 2>&1 | Out-Null
docker run -d --name lab-target -p 127.0.0.1:5000:5000 lab-app:local 2>&1 | Out-Null
$up = $false
1..20 | ForEach-Object { if (-not $up) { try { Invoke-WebRequest http://127.0.0.1:5000/ -UseBasicParsing -TimeoutSec 2 | Out-Null; $up = $true } catch { Start-Sleep 1 } } }
docker run --rm -v "${dast}:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:5000 -r zap-baseline.html -J zap-baseline.json -I 2>&1 | Out-File "$dast\zap-baseline.log" -Encoding utf8
docker rm -f lab-target lab-registry 2>&1 | Out-Null
Write-Host 'done'
