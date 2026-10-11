# Lab signing: Cosign key-based sign-blob + verify-blob, with a tamper test.
# Production uses keyless signing in CI and image admission; see README.
param([string]$Artifact = "$PSScriptRoot\dist\lab-app.zip")

$ErrorActionPreference = 'Continue'
$cosign = 'cosign-windows-amd64'
$results = "$PSScriptRoot\results"
New-Item -ItemType Directory -Force $results, "$PSScriptRoot\dist" | Out-Null

# Lab-only password; the private key is git-ignored and never reused.
$env:COSIGN_PASSWORD = 'lab-only-password'
if (-not (Test-Path "$PSScriptRoot\cosign.key")) {
    Push-Location $PSScriptRoot
    & $cosign generate-key-pair 2>&1 | Out-Null
    Pop-Location
}

$bundle = "$Artifact.bundle"
$log = @()
$log += "== sign-blob"
$log += & $cosign sign-blob --yes --key "$PSScriptRoot\cosign.key" --use-signing-config=false --tlog-upload=false --bundle $bundle $Artifact 2>&1 | ForEach-Object { "$_" }

$log += "== verify-blob (original artifact)"
$log += & $cosign verify-blob --key "$PSScriptRoot\cosign.pub" --bundle $bundle --insecure-ignore-tlog $Artifact 2>&1 | ForEach-Object { "$_" }
$okExit = $LASTEXITCODE

$tampered = "$PSScriptRoot\dist\tampered.zip"
Copy-Item $Artifact $tampered -Force
Add-Content $tampered 'x'
$log += "== verify-blob (tampered artifact, expected to FAIL)"
$log += & $cosign verify-blob --key "$PSScriptRoot\cosign.pub" --bundle $bundle --insecure-ignore-tlog $tampered 2>&1 | ForEach-Object { "$_" }
$badExit = $LASTEXITCODE
Remove-Item $tampered -Force

$log += ""
$log += "original verify exit code : $okExit   (0 = signature valid)"
$log += "tampered verify exit code : $badExit   (non-zero = rejected)"
$log | Set-Content "$results\cosign.txt" -Encoding utf8
$log | Write-Host

if ($okExit -ne 0 -or $badExit -eq 0) { exit 1 }
exit 0
