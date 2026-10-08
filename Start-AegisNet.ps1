$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
# This convenience launcher reuses the verified portable PostgreSQL cluster in this workspace.
# Portable source users can instead configure PostgreSQL as described in README.md.
$workspace = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$pgRoot = Join-Path $workspace 'work/postgres'
$pgCtl = Join-Path $pgRoot 'pgsql/bin/pg_ctl.exe'
$pgData = Join-Path $pgRoot 'data'
if ((Test-Path -LiteralPath $pgCtl) -and (Test-Path -LiteralPath $pgData)) {
    & $pgCtl -D $pgData status | Out-Null
    if ($LASTEXITCODE -ne 0) {
        $arguments = @('-D', ('"' + $pgData + '"'), '-l', ('"' + (Join-Path $pgRoot 'server.log') + '"'), '-o', '"-p 55432 -h 127.0.0.1"', 'start')
        $started = Start-Process -FilePath $pgCtl -ArgumentList $arguments -WindowStyle Hidden -PassThru
        $started.WaitForExit() # Wait for pg_ctl only; PostgreSQL intentionally stays running.
        if ($started.ExitCode -ne 0) { throw 'PostgreSQL failed to start; inspect work/postgres/server.log.' }
    }
}
$python = Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $python)) { throw 'Run uv sync --locked first. See README.md.' }
& $python -m scripts.serve

