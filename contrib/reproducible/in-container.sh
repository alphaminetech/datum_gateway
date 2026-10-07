#!/bin/bash
# Runs inside the build container that build.sh starts. Not meant to be run on a host.
set -euo pipefail
umask 022
export DEBIAN_FRONTEND=noninteractive LC_ALL=C TZ=UTC
: "${TARGET:?}" "${UBUNTU:?}" "${IMAGE:?}" "${APT_SNAPSHOT:?}" "${BUILD_DIR:?}" "${LABEL:?}" "${COMMIT:?}" "${SRC:?}"
JOBS=${JOBS:-4}
NAME=datum_gateway-$LABEL-g${COMMIT:0:12}-$TARGET
WORK=/work

if [ "${1:-root}" = root ]; then
  # ---- 1. packages: only the Ubuntu archive as it was at APT_SNAPSHOT -------------------------------------------------
  SNAP=https://snapshot.ubuntu.com/ubuntu/$APT_SNAPSHOT
  rm -f /etc/apt/sources.list.d/*
  printf 'deb %s %s main universe\n' "$SNAP" "$TARGET" "$SNAP" "$TARGET-updates" "$SNAP" "$TARGET-security" > /etc/apt/sources.list
  # A snapshot's index files are past their "Valid-Until" date by design.
  APT=(apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=3)
  # The base image holds no CA certificates, so the server's TLS certificate cannot be checked until
  # ca-certificates is installed. APT checks the archive's signatures with the keys in the image either
  # way; that check is what authenticates the packages.
  NOTLS=(-o Acquire::https::Verify-Peer=false -o Acquire::https::Verify-Host=false)
  "${APT[@]}" "${NOTLS[@]}" update -qq
  "${APT[@]}" "${NOTLS[@]}" install -y -qq --no-install-recommends ca-certificates > /dev/null
  "${APT[@]}" update -qq
  "${APT[@]}" install -y -qq --no-install-recommends build-essential cmake pkg-config git \
    libcurl4-openssl-dev libjansson-dev libmicrohttpd-dev libsodium-dev > /dev/null

  # ---- 2. an unprivileged user builds, in a fixed directory -----------------------------------------------------------
  useradd -m builder
  install -d -o builder -g builder "$(dirname "$BUILD_DIR")" "$WORK"
  git config --system --add safe.directory '*'      # /src belongs to the host user
  runuser -u builder -- env HOME=/home/builder bash /in-container.sh build

  # ---- 3. hand the results to the host user ---------------------------------------------------------------------------
  dpkg-query -W -f='${Package}=${Version}\n' | sort > "$WORK/packages.txt"
  install -m 0644 "$WORK/$NAME.tar.gz" "/out/$NAME.tar.gz"
  install -m 0644 "$WORK/stage/$NAME/BUILDINFO" "/out/$NAME.BUILDINFO"
  install -m 0644 "$WORK/packages.txt" "/out/$NAME.packages.txt"
  install -m 0644 "$WORK/selftest.log" "/out/$NAME.selftest.log"
  chown "${HOST_UID:-0}:${HOST_GID:-0}" "/out/$NAME".*
  exit 0
fi

# ---- the build itself, as the unprivileged user ----------------------------------------------------------------------
git -c init.defaultBranch=build init -q "$BUILD_DIR"
cd "$BUILD_DIR"
git fetch -q --no-tags --depth 1 "$SRC" "$COMMIT"
git checkout -q --detach FETCH_HEAD
[ "$(git rev-parse HEAD)" = "$COMMIT" ] || { echo "the checkout is not commit $COMMIT"; exit 1; }
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
export SOURCE_DATE_EPOCH

cmake -S . -B . > "$WORK/cmake.log" 2>&1 || { tail -20 "$WORK/cmake.log"; exit 1; }
make -j"$JOBS" > "$WORK/make.log" 2>&1 || { tail -30 "$WORK/make.log"; exit 1; }

# The version the gateway reports is this commit, exactly: no "+" (modified tree), no tag.
[ -z "$(git status --porcelain --untracked-files=no)" ] || { echo "the build changed tracked files"; exit 1; }
[ "$(cat git_version.h)" = "#define GIT_COMMIT_HASH \"$COMMIT\"" ] || { echo "unexpected git_version.h:"; cat git_version.h; exit 1; }
PROTOCOL_VERSION=$(sed -n 's/^#define DATUM_PROTOCOL_VERSION "\([^"]*\)".*/\1/p' src/datum_protocol.h)
[ -n "$PROTOCOL_VERSION" ] || { echo "DATUM_PROTOCOL_VERSION not found"; exit 1; }

# The gateway's own test suite must pass.
rc=0
./datum_gateway --test > "$WORK/selftest.log" 2>&1 || rc=$?
if [ "$rc" != 0 ] || grep -q "TEST FAILED" "$WORK/selftest.log"; then
  tail -20 "$WORK/selftest.log"; echo "the gateway's self-test FAILED (exit $rc)"; exit 1
fi

# ---- the archive -----------------------------------------------------------------------------------------------------
STAGE=$WORK/stage/$NAME
mkdir -p "$STAGE"
install -m 0755 datum_gateway "$STAGE/datum_gateway"
install -m 0644 LICENSE "$STAGE/LICENSE"
{
  echo "name=datum_gateway $LABEL"
  echo "source_commit=$COMMIT"
  echo "client_version=$PROTOCOL_VERSION/$COMMIT"
  echo "binary_sha256=$(sha256sum datum_gateway | cut -d' ' -f1)"
  echo "target=Ubuntu $UBUNTU ($TARGET), x86-64"
  echo "needs=$(objdump -T datum_gateway | grep -oE 'GLIBC_[0-9.]+' | sort -Vu | tail -1)"
  echo "image=$IMAGE"
  echo "apt_snapshot=$APT_SNAPSHOT"
  echo "build_dir=$BUILD_DIR"
  echo "build_commands=cmake -S . -B . && make"
  echo "source_date_epoch=$SOURCE_DATE_EPOCH"
  echo "toolchain: $(gcc --version | head -1)"
  echo "toolchain: $(cmake --version | head -1)"
  echo "toolchain: $(ld --version | head -1)"
  dpkg-query -W -f='package: ${Package}=${Version}\n' libc6 libc6-dev linux-libc-dev binutils make cmake \
    libcurl4-openssl-dev libjansson-dev libmicrohttpd-dev libsodium-dev
} > "$STAGE/BUILDINFO"
chmod 0644 "$STAGE/BUILDINFO"
tar --sort=name --format=gnu --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" \
  -C "$WORK/stage" -cf - "$NAME" | gzip -n -9 > "$WORK/$NAME.tar.gz"
