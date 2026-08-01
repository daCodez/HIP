#!/bin/sh
set -eu

version=${1:-}
case "$version" in
    ""|*[!A-Za-z0-9._+-]*)
        echo "Usage: release-metadata.sh <safe-release-version>" >&2
        exit 2
        ;;
esac

repository_root=$(git rev-parse --show-toplevel 2>/dev/null) || {
    echo "HIP release metadata must be generated from a Git checkout." >&2
    exit 1
}
cd "$repository_root"

if ! git diff --quiet --ignore-submodules -- ||
   ! git diff --cached --quiet --ignore-submodules -- ||
   [ -n "$(git ls-files --others --exclude-standard)" ]; then
    echo "Refusing to release an uncommitted HIP worktree." >&2
    exit 1
fi

revision=$(git rev-parse --verify HEAD^{commit})
case "$revision" in
    *[!0-9a-f]*|"")
        echo "HIP release revision is invalid." >&2
        exit 1
        ;;
esac

printf "HIP_RELEASE_REVISION='%s'\n" "$revision"
printf "HIP_RELEASE_VERSION='%s'\n" "$version"
