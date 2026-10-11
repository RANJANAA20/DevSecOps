# Image-level stages. Requires a working Docker engine; NOT yet run on this machine (virtualization disabled).
# Flow: build -> Trivy image scan -> Syft SBOM -> push to local registry -> Cosign sign by digest -> verify -> ZAP baseline.
param([string]$Target = "$PSScriptRoot\..\app-or-lab-target")

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$img = 'lab-app:local'
$reg = 'localhost:5001'
$out = "$root\devsecops\container-scan\results"
$env:COSIGN_PASSWORD = 'lab-only-password'
$cosign = 'cosign-windows-amd64'
$key = "$root\devsecops\signing\cosign.key"
$pub = "$root\devsecops\signing\cosign.pub"

docker build -t $img $Target

trivy image --quiet --format json --output "$out\trivy-image.json" $img
trivy image --quiet --severity HIGH,CRITICAL --format table --output "$out\trivy-image.txt" $img
syft $img -q -o "spdx-json=$out\sbom-image.spdx.json"

# Local registry stands in for the production registry.
docker rm -f lab-registry 2>$null | Out-Null
docker run -d --name lab-registry -p 5001:5000 registry:2 | Out-Null
docker tag $img "$reg/lab-app:local"
docker push "$reg/lab-app:local"
$digest = (docker inspect --format '{{index .RepoDigests 0}}' "$reg/lab-app:local")

# Sign by digest (never by tag); local key and no transparency log, as in the blob lab.
& $cosign sign --yes --key $key --tlog-upload=false --allow-insecure-registry $digest
& $cosign verify --key $pub --insecure-ignore-tlog --allow-insecure-registry $digest | Out-File "$root\devsecops\signing\results\cosign-image.txt" -Encoding utf8

# Baseline DAST with the official container (passive only).
docker run -d --name lab-target -p 5000:5000 $img | Out-Null
docker run --rm --network host -v "${root}\devsecops\dast\results:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable `
    zap-baseline.py -t http://host.docker.internal:5000 -r zap-baseline.html -J zap-baseline.json -I
docker rm -f lab-target lab-registry | Out-Null
