$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$toolRoot = Join-Path $repositoryRoot '.postgres-tools'
$pgControl = Join-Path $toolRoot 'pgsql/bin/pg_ctl.exe'
$dataDirectory = Join-Path $toolRoot 'data'
& $pgControl status -D $dataDirectory
if ($LASTEXITCODE -eq 0) { $global:LASTEXITCODE = 0; return }
$controlProcess = Start-Process -FilePath $pgControl -ArgumentList @('start', '-D', "`"$dataDirectory`"", '-l', "`"$(Join-Path $toolRoot 'postgres.log')`"", '-w') -WindowStyle Hidden -PassThru
$controlProcess.WaitForExit()
if ($controlProcess.ExitCode -ne 0) { throw 'PostgreSQL did not start; check .postgres-tools/postgres.log.' }
Write-Output 'PostgreSQL listening on 127.0.0.1:5432.'
$global:LASTEXITCODE = 0
