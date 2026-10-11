# Starts the lab app on loopback only, runs Wapiti against it, then stops the app.
# Active DAST sends attack payloads: only run it against systems you own and are authorised to test.
param([string]$Target = "$PSScriptRoot\..\app-or-lab-target", [int]$Port = 5000)

$ErrorActionPreference = 'Continue'
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$out = "$PSScriptRoot\results"; New-Item -ItemType Directory -Force $out | Out-Null
$url = "http://127.0.0.1:$Port/"

$app = Start-Process "$root\.venv\Scripts\python.exe" -ArgumentList "`"$Target\app.py`"" -PassThru -WindowStyle Hidden
try {
    $up = $false
    1..20 | ForEach-Object { if (-not $up) { try { Invoke-WebRequest $url -UseBasicParsing -TimeoutSec 2 | Out-Null; $up = $true } catch { Start-Sleep 1 } } }
    if (-not $up) { throw "lab app did not start on $url" }

    $env:PYTHONUTF8 = '1'
    # Seed URLs with parameters so the crawler finds the injectable endpoints.
    $seeds = @("${url}user?name=alice", "${url}ping?host=127.0.0.1")
    $args = @('-u', $seeds[0], '-u', $seeds[1], '--scope', 'domain', '-m', 'sql,exec,xss,http_headers,cookieflags,csp,backup,file',
        '--max-scan-time', '240', '-f', 'json', '-o', "$out\wapiti.json", '--flush-session', '-v', '1')
    & "$root\.venv-dast\Scripts\wapiti.exe" @args 2>&1 | Out-File "$out\wapiti.log" -Encoding utf8
    & "$root\.venv-dast\Scripts\wapiti.exe" -u $seeds[0] -u $seeds[1] --scope domain -m 'sql,exec,xss,http_headers,cookieflags,csp,backup,file' --max-scan-time 240 -f html -o "$out\wapiti.html" --flush-session -v 0 2>&1 | Out-Null
}
finally {
    if ($app) { & taskkill /PID $app.Id /T /F 2>&1 | Out-Null }
}

$high = 0; $other = 0
if (Test-Path "$out\wapiti.json") {
    $r = Get-Content "$out\wapiti.json" -Raw | ConvertFrom-Json
    foreach ($p in $r.vulnerabilities.PSObject.Properties) {
        $n = @($p.Value).Count
        if ($p.Name -match 'SQL|Command|Commands') { $high += $n } else { $other += $n }
    }
    $summary = @($r.vulnerabilities.PSObject.Properties | ForEach-Object { "{0}: {1}" -f $_.Name, @($_.Value).Count })
    $summary | Set-Content "$out\wapiti-summary.txt" -Encoding utf8
}
[pscustomobject]@{ High = $high; Other = $other }
