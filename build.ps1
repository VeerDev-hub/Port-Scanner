param(
    [string]$Python = "python",
    [string]$AppName = "portspectre",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

if ($Clean) {
    if (Test-Path "build") { Remove-Item "build" -Recurse -Force }
    if (Test-Path "dist") { Remove-Item "dist" -Recurse -Force }
    if (Test-Path "$AppName.spec") { Remove-Item "$AppName.spec" -Force }
}

Write-Host "[1/4] Installing build dependency: pyinstaller"
& $Python -m pip install --upgrade pyinstaller

Write-Host "[2/4] Building executable"
& $Python -m PyInstaller --onefile --name $AppName portscanner_cli.py

if (-not (Test-Path "dist\$AppName.exe")) {
    throw "Build failed: dist\$AppName.exe not found."
}

Write-Host "[3/4] Build artifact"
Write-Host "dist\$AppName.exe"

Write-Host "[4/4] Done"
