param([int]$HttpPort = 80, [int]$HttpsPort = 443)
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($env:MASTER_KEY)) { throw 'Set MASTER_KEY to your saved NFC master key before starting.' }
$credentials = Get-Content -LiteralPath (Join-Path $repositoryRoot 'local-secrets.json') -Raw | ConvertFrom-Json
$env:DATABASE_URL = $credentials.DATABASE_URL
$env:ADMIN_TOKEN = $credentials.ADMIN_TOKEN
if ([string]::IsNullOrWhiteSpace($env:CLOUDFLARE_PROXY)) { $env:CLOUDFLARE_PROXY = '0' }
if ([string]::IsNullOrWhiteSpace($env:DERIVE_MODE)) { $env:DERIVE_MODE = 'legacy' }
$env:LISTEN_ADDR = "0.0.0.0:$HttpPort"
$env:HTTPS_ADDR = "0.0.0.0:$HttpsPort"
$env:TLS_CERT = Join-Path $repositoryRoot '.local-tls/cert.pem'
$env:TLS_KEY = Join-Path $repositoryRoot '.local-tls/key.pem'
$backendProcess = Start-Process -FilePath (Join-Path $repositoryRoot 'nfctag.exe') -WorkingDirectory $repositoryRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $repositoryRoot 'backend.stdout.log') -RedirectStandardError (Join-Path $repositoryRoot 'backend.stderr.log') -PassThru
Start-Sleep -Seconds 1
$backendProcess.Refresh()
if ($backendProcess.HasExited) { throw 'Backend startup failed; check backend.stderr.log.' }
Write-Output "Backend started, PID $($backendProcess.Id), HTTP $HttpPort and HTTPS $HttpsPort."
