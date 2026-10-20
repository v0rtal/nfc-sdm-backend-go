$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$toolRoot = Join-Path $repositoryRoot '.postgres-tools'
$binDirectory = Join-Path $toolRoot 'pgsql/bin'
$dataDirectory = Join-Path $toolRoot 'data'
$secretPath = Join-Path $repositoryRoot 'local-secrets.json'
if (Test-Path -LiteralPath $dataDirectory) { throw 'Database directory already exists; use start-postgres.ps1 to preserve existing data.' }
if (Test-Path -LiteralPath $secretPath) { throw 'Secrets already exist; preserve them rather than generating new credentials.' }
function New-RandomHex {
    $randomBytes = New-Object byte[] 32
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($randomBytes) } finally { $generator.Dispose() }
    return ([BitConverter]::ToString($randomBytes)).Replace('-', '').ToLowerInvariant()
}
$databasePassword = New-RandomHex
$credentials = @{ DATABASE_URL = "postgres://nfctag_owner:${databasePassword}@127.0.0.1:5432/nfctag?sslmode=disable"; ADMIN_TOKEN = (New-RandomHex) }
$credentials | ConvertTo-Json | Set-Content -LiteralPath $secretPath -Encoding ASCII
# Restrict local credentials to the current Windows user.
$account = [Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe $secretPath /inheritance:r /grant:r "${account}:(F)" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict credential file permissions.' }
$passwordPath = Join-Path $toolRoot 'init-password.tmp'
Set-Content -LiteralPath $passwordPath -Value $databasePassword -Encoding ASCII
& icacls.exe $passwordPath /inheritance:r /grant:r "${account}:(F)" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict temporary credential permissions.' }
try {
    & (Join-Path $binDirectory 'initdb.exe') -D $dataDirectory -U nfctag_owner --auth=scram-sha-256 --encoding=UTF8 --locale=C "--pwfile=$passwordPath"
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL initialization failed.' }
} finally { Remove-Item -LiteralPath $passwordPath -Force }
Add-Content -LiteralPath (Join-Path $dataDirectory 'postgresql.conf') -Value "`nlisten_addresses = '127.0.0.1'`nport = 5432`n"
& (Join-Path $PSScriptRoot 'start-postgres.ps1')
$env:PGPASSWORD = $databasePassword
try {
    & (Join-Path $binDirectory 'createdb.exe') -h 127.0.0.1 -p 5432 -U nfctag_owner nfctag
    if ($LASTEXITCODE -ne 0) { throw 'Database creation failed.' }
} finally { Remove-Item Env:PGPASSWORD }
Write-Output 'Local PostgreSQL ready. Database connection and management password are in local-secrets.json.'
