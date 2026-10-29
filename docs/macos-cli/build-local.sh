#!/usr/bin/env bash
# Copyright 2026 The Outline Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Builds a universal (arm64 + x86_64) macOS binary using only Go and the Xcode
# Command Line Tools, then signs it ad hoc. Works on Intel and Apple Silicon
# hosts: the other architecture is cross-compiled with clang's -arch flag.
#
# It writes only to output/macos-cli/ and never runs the binary with root or
# touches network settings. The only run is the smoke test (SMOKE_ARGS).
#
# Usage:
#   docs/macos-cli/build-local.sh              # build both slices + universal
#   docs/macos-cli/build-local.sh build ARCH   # build one slice (arm64|amd64)
#   docs/macos-cli/build-local.sh universal    # lipo + sign existing slices
#
# Environment overrides:
#   PKG         Go package to build      (default ./client/go/outline/macoscli)
#   NAME        output file name prefix  (default outline-cli)
#   VERSION     embedded main.version    (default: git describe)
#   MIN_MACOS   minimum macOS version    (default 12.0, Go 1.25's minimum)
#   SMOKE_ARGS  args for the smoke run   (default "version")

set -euo pipefail

cd "$(dirname "$0")/../.."

PKG="${PKG:-./client/go/outline/macoscli}"
NAME="${NAME:-outline-cli}"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
MIN_MACOS="${MIN_MACOS:-12.0}"
SMOKE_ARGS="${SMOKE_ARGS:-version}"
OUT="output/macos-cli"

die() {
  echo "build-local: $*" >&2
  exit 1
}

[[ "$(uname -s)" == "Darwin" ]] || die "must run on macOS"

clang_arch() {
  case "$1" in
    arm64) echo arm64 ;;
    amd64) echo x86_64 ;;
    *) die "unknown arch '$1' (want arm64 or amd64)" ;;
  esac
}

# Prints the minimum macOS version recorded in one slice of a Mach-O file.
min_os() {
  otool -arch "$2" -l "$1" | awk '/LC_BUILD_VERSION/ {f=1} f && $1 == "minos" {print $2; exit}'
}

build_slice() {
  local arch="$1" carch bin
  carch="$(clang_arch "$arch")"
  bin="$OUT/$NAME-$arch"
  mkdir -p "$OUT"
  echo "==> building $PKG for darwin/$arch (min macOS $MIN_MACOS)"
  # The version-min flags must be in CGO_CFLAGS/CGO_LDFLAGS (not only
  # MACOSX_DEPLOYMENT_TARGET) so they are part of Go's build cache key.
  # Otherwise stale cgo objects built for the host's macOS version get reused.
  GOOS=darwin GOARCH="$arch" CGO_ENABLED=1 \
    CC="clang -arch $carch" \
    MACOSX_DEPLOYMENT_TARGET="$MIN_MACOS" \
    CGO_CFLAGS="-O2 -g -mmacosx-version-min=$MIN_MACOS" \
    CGO_LDFLAGS="-mmacosx-version-min=$MIN_MACOS" \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$bin" "$PKG"
  [[ "$(lipo -archs "$bin")" == "$carch" ]] || die "$bin is not $carch"
  [[ "$(min_os "$bin" "$carch")" == "$MIN_MACOS" ]] || die "$bin minos is not $MIN_MACOS"
  echo "    $bin ok"
}

make_universal() {
  local uni="$OUT/$NAME"
  [[ -f "$OUT/$NAME-arm64" && -f "$OUT/$NAME-amd64" ]] || die "missing slices in $OUT"
  echo "==> creating universal binary $uni"
  lipo -create -output "$uni" "$OUT/$NAME-amd64" "$OUT/$NAME-arm64"
  # lipo invalidates the linker's ad hoc signature, and Apple Silicon refuses
  # to run unsigned code, so re-sign ad hoc.
  codesign --force --sign - "$uni"
  codesign --verify --strict --verbose=2 "$uni"
  lipo -info "$uni"
  for carch in x86_64 arm64; do
    [[ "$(min_os "$uni" "$carch")" == "$MIN_MACOS" ]] || die "$carch slice minos is not $MIN_MACOS"
  done
  echo "==> smoke test on the $(uname -m) slice: $NAME $SMOKE_ARGS"
  # shellcheck disable=SC2086 # SMOKE_ARGS is intentionally word-split.
  "./$uni" $SMOKE_ARGS
  (cd "$OUT" && shasum -a 256 "$NAME" | tee "$NAME.sha256")
}

case "${1:-all}" in
  all)
    build_slice arm64
    build_slice amd64
    make_universal
    ;;
  build)
    build_slice "${2:?usage: build-local.sh build ARCH}"
    ;;
  universal)
    make_universal
    ;;
  *)
    die "unknown command '$1' (want all, build ARCH or universal)"
    ;;
esac
