#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3}"
APP_NAME="${APP_NAME:-portspectre}"

if [[ "${1:-}" == "--clean" ]]; then
  rm -rf build dist "${APP_NAME}.spec"
fi

echo "[1/4] Installing build dependency: pyinstaller"
"$PYTHON_BIN" -m pip install --upgrade pyinstaller

echo "[2/4] Building executable"
"$PYTHON_BIN" -m PyInstaller --onefile --name "$APP_NAME" portscanner_cli.py

if [[ ! -f "dist/${APP_NAME}" ]]; then
  echo "Build failed: dist/${APP_NAME} not found." >&2
  exit 1
fi

echo "[3/4] Build artifact"
echo "dist/${APP_NAME}"

echo "[4/4] Done"
