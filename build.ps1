#requires -Version 5.1
# Build a portable release and copy it to .\dist
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

# cargo writes progress to stderr; with ErrorActionPreference=Stop PowerShell
# would treat that as a fatal NativeCommandError, so relax it for this call.
$ErrorActionPreference = 'Continue'
cargo build --release
$code = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($code -ne 0) { throw "cargo build failed" }

New-Item -ItemType Directory -Force .\dist | Out-Null
Copy-Item .\target\release\obhod.exe .\dist\obhod.exe -Force
# Create/refresh the default brand file next to the exe so it is easy to edit.
& .\dist\obhod.exe --brand | Out-Null

$size = [math]::Round((Get-Item .\dist\obhod.exe).Length / 1MB, 2)
Write-Host "OK: dist\obhod.exe ($size MB)"
