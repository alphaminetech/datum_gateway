#!/usr/bin/env bash
# Reproducible build of the DATUM gateway for Ubuntu 22.04 (jammy) and Ubuntu 24.04 (noble).
#
#   contrib/reproducible/build.sh jammy|noble [OUTDIR]
#
# Builds one commit of this repository inside a container and writes, to OUTDIR (default ./out):
#
#   datum_gateway-<label>-g<commit12>-<jammy|noble>.tar.gz      datum_gateway, BUILDINFO, LICENSE
#   datum_gateway-<label>-g<commit12>-<jammy|noble>.BUILDINFO   the same BUILDINFO, next to the archive
#   ....packages.txt, ....selftest.log                          every package in the container; the self-test output
#
# Everything that goes into the binary is fixed:
#   - the container image, by digest;
#   - every package, taken from the Ubuntu archive as it was at APT_SNAPSHOT (snapshot.ubuntu.com);
#   - the source, by full commit hash, fetched without tags into a fixed directory (BUILD_DIR);
#   - SOURCE_DATE_EPOCH (the commit's time), umask, locale and time zone;
#   - the archive: sorted names, owner 0:0, the commit's time as mtime, gzip without a name or time stamp.
# Two runs, at any time and on any x86-64 machine, give the same sha256 for the binary and for the archive.
#
# Environment:
#   COMMIT   full commit hash to build       (default: HEAD of this checkout)
#   SOURCE   git repository to fetch it from (default: this checkout; an https URL works too, and then
#            COMMIT must be given)
#   LABEL    release label used in file names (default: r3.1)
#   DOCKER   container command                (default: docker; for example "sudo docker" or podman)
#   CONTAINER_NAME, DOCKER_RUN_ARGS           name of the container, extra arguments for "run"
#   JOBS     parallel compile jobs            (default: 4; does not change the result)
set -euo pipefail
umask 022

usage(){ sed -n '2,6p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2; }
TARGET=${1:-}
OUT=${2:-out}
case "$TARGET" in
  # image index digests of ubuntu:22.04 and ubuntu:24.04 on Docker Hub (linux/amd64 is used)
  jammy) UBUNTU=22.04; IMAGE=ubuntu@sha256:5ec03bb3441e8b0bf3b4f9cd4629a1ae763010dc3035bb8da3ae6cf026486401;;
  noble) UBUNTU=24.04; IMAGE=ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55;;
  *) usage;;
esac
APT_SNAPSHOT=20261006T000000Z
BUILD_DIR=/build/datum_gateway
LABEL=${LABEL:-r3.1}
DOCKER=${DOCKER:-docker}
JOBS=${JOBS:-4}

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
MOUNT=()
case "${SOURCE:-}" in
  http://*|https://*|git://*|ssh://*)
    SRC=$SOURCE
    : "${COMMIT:?SOURCE is a URL: set COMMIT to the full commit hash to build}";;
  *)
    SOURCE=${SOURCE:-$(git -C "$HERE" rev-parse --show-toplevel)}
    SOURCE=$(cd "$SOURCE" && pwd)
    COMMIT=${COMMIT:-$(git -C "$SOURCE" rev-parse HEAD)}
    git -C "$SOURCE" cat-file -e "$COMMIT^{commit}" || { echo "commit $COMMIT is not in $SOURCE" >&2; exit 1; }
    SRC=file:///src
    MOUNT=(-v "$SOURCE:/src:ro");;
esac
[[ $COMMIT =~ ^[0-9a-f]{40}$ ]] || { echo "COMMIT must be a full 40-character commit hash" >&2; exit 1; }
[[ $LABEL =~ ^[A-Za-z0-9._]+$ ]] || { echo "LABEL may hold letters, digits, dots and underscores" >&2; exit 1; }

mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
NAME=datum_gateway-$LABEL-g${COMMIT:0:12}-$TARGET
echo "building $COMMIT for Ubuntu $UBUNTU ($TARGET) in $IMAGE"
# shellcheck disable=SC2086
$DOCKER run --rm --platform linux/amd64 --name "${CONTAINER_NAME:-datum-gateway-build-$TARGET-$$}" ${DOCKER_RUN_ARGS:-} \
  -e TARGET="$TARGET" -e UBUNTU="$UBUNTU" -e IMAGE="$IMAGE" -e APT_SNAPSHOT="$APT_SNAPSHOT" -e BUILD_DIR="$BUILD_DIR" \
  -e LABEL="$LABEL" -e COMMIT="$COMMIT" -e SRC="$SRC" -e JOBS="$JOBS" -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  ${MOUNT[@]+"${MOUNT[@]}"} -v "$HERE/in-container.sh:/in-container.sh:ro" -v "$OUT:/out" \
  "$IMAGE" bash /in-container.sh

echo
echo "commit   $COMMIT"
echo "client   $(sed -n 's/^client_version=//p' "$OUT/$NAME.BUILDINFO")"
echo "binary   $(sed -n 's/^binary_sha256=//p' "$OUT/$NAME.BUILDINFO")  datum_gateway"
echo "archive  $(sha256sum "$OUT/$NAME.tar.gz" | cut -d' ' -f1)  $NAME.tar.gz"
