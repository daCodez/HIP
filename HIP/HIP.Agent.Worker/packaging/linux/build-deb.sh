#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROJECT="${ROOT_DIR}/HIP.Agent.Worker/HIP.Agent.Worker.csproj"
CONFIGURATION="${1:-Release}"
VERSION="${2:-0.1.0}"
RUNTIME="linux-x64"
PKG_NAME="hip-agent-worker"
ARTIFACT_DIR="${ROOT_DIR}/out/deb"
PUBLISH_DIR="${ARTIFACT_DIR}/publish"
STAGE_DIR="${ARTIFACT_DIR}/${PKG_NAME}_${VERSION}"
DEB_PATH="${ARTIFACT_DIR}/${PKG_NAME}_${VERSION}_${RUNTIME}.deb"

rm -rf "${PUBLISH_DIR}" "${STAGE_DIR}"
mkdir -p "${PUBLISH_DIR}" "${STAGE_DIR}/DEBIAN" "${STAGE_DIR}/opt/${PKG_NAME}" "${STAGE_DIR}/usr/bin"

echo "Publishing HIP.Agent.Worker (${CONFIGURATION})..."
dotnet publish "${PROJECT}" -c "${CONFIGURATION}" -r "${RUNTIME}" --self-contained false -o "${PUBLISH_DIR}"

cp -a "${PUBLISH_DIR}/." "${STAGE_DIR}/opt/${PKG_NAME}/"

cat > "${STAGE_DIR}/usr/bin/hip-agent-worker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec /usr/bin/dotnet /opt/hip-agent-worker/HIP.Agent.Worker.dll "$@"
EOF
chmod 0755 "${STAGE_DIR}/usr/bin/hip-agent-worker"

INSTALLED_SIZE_KB="$(du -sk "${STAGE_DIR}" | awk '{print $1}')"

cat > "${STAGE_DIR}/DEBIAN/control" <<EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: amd64
Maintainer: HIP Team <devnull@hip.local>
Depends: dotnet-runtime-10.0
Installed-Size: ${INSTALLED_SIZE_KB}
Description: HIP Agent Worker scaffold package
 Phase-2 scaffold package for HIP.Agent.Worker.
 Includes executable wrapper and published worker binaries.
EOF

dpkg-deb --build "${STAGE_DIR}" "${DEB_PATH}"
echo "DEB scaffold generated: ${DEB_PATH}"
