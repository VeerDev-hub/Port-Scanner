#!/usr/bin/env bash
set -euo pipefail

APP_NAME="${APP_NAME:-portspectre}"
VERSION="${VERSION:-1.0.0}"
ARCH="${ARCH:-amd64}"
MAINTAINER="${MAINTAINER:-PortSpectre Maintainer <maintainer@example.com>}"
OUT_DIR="${OUT_DIR:-dist}"
PKG_ROOT="${PKG_ROOT:-pkg-deb}"

if [[ ! -f "dist/${APP_NAME}" ]]; then
  echo "Binary dist/${APP_NAME} not found. Run ./build.sh first." >&2
  exit 1
fi

rm -rf "${PKG_ROOT}"
mkdir -p "${PKG_ROOT}/DEBIAN" "${PKG_ROOT}/usr/local/bin" "${PKG_ROOT}/usr/share/doc/${APP_NAME}"

cat > "${PKG_ROOT}/DEBIAN/control" <<EOF
Package: ${APP_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: ${MAINTAINER}
Description: PortSpectre CLI fast multi-mode port scanner
EOF

install -m 0755 "dist/${APP_NAME}" "${PKG_ROOT}/usr/local/bin/${APP_NAME}"
install -m 0644 "README.md" "${PKG_ROOT}/usr/share/doc/${APP_NAME}/README.md"
install -m 0644 "License.txt" "${PKG_ROOT}/usr/share/doc/${APP_NAME}/LICENSE"

mkdir -p "${OUT_DIR}"
dpkg-deb --build "${PKG_ROOT}" "${OUT_DIR}/${APP_NAME}_${VERSION}_${ARCH}.deb"
echo "Created ${OUT_DIR}/${APP_NAME}_${VERSION}_${ARCH}.deb"
