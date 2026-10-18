#!/usr/bin/env bash
# release.sh builds the release archives into dist/: per platform, a stripped -trimpath binary in
# dist/mintrun_<version>_<os>_<arch>/ with LICENSE and README.md, packed as a .tar.gz of that folder,
# then dist/SHA256SUMS. It signs and notarizes nothing (see the end).
# Usage: scripts/release.sh vX.Y.Z, or VERSION=vX.Y.Z scripts/release.sh. Run it in the main
# checkout at the release tag: Go stamps vcs.revision from the enclosing .git directory (rule 49).
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=${1:-${VERSION:-}}
# The version goes into -ldflags and file names, so nothing but a semver tag gets through.
re='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
if ! [[ $VERSION =~ $re ]]; then
	echo "usage: scripts/release.sh vX.Y.Z (or VERSION=vX.Y.Z), got '$VERSION'" >&2
	exit 2
fi

rm -rf dist
mkdir dist
for target in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64; do
	os=${target%/*} arch=${target#*/}
	name=mintrun_${VERSION}_${os}_${arch}
	echo "== $name"
	# The code has no cgo, and a cross build must not depend on this host's C toolchain.
	CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=$VERSION" \
		-o "dist/$name/mintrun" ./cmd/mintrun
	# -trimpath keeps this machine's paths out of the binary (rule 3); refuse one that still has any.
	# Not strings | grep -q: under pipefail, the SIGPIPE grep's early exit sends strings reads as a miss.
	if LC_ALL=C grep -a -q -E '/Users/|/home/' "dist/$name/mintrun"; then
		echo "dist/$name/mintrun holds a /Users/ or /home/ path" >&2
		exit 1
	fi
	cp LICENSE README.md "dist/$name/"
	# macOS tar would otherwise record the owner's user name, xattrs, and a ._ file per entry.
	COPYFILE_DISABLE=1 tar --owner=0 --group=0 --numeric-owner --no-xattrs -czf "dist/$name.tar.gz" -C dist "$name"
done

cd dist
if command -v sha256sum >/dev/null; then sha256sum mintrun_*.tar.gz; else shasum -a 256 mintrun_*.tar.gz; fi >SHA256SUMS
cat SHA256SUMS

# Signing and notarizing are left to the maintainer:
# - Checksums: gpg --armor --detach-sign dist/SHA256SUMS (writes SHA256SUMS.asc), or keyless
#   cosign sign-blob --bundle dist/SHA256SUMS.sigstore.json dist/SHA256SUMS.
# - macOS: Gatekeeper wants each darwin binary signed with a Developer ID and notarized. Sign it right
#   after its go build, before it is packed, because signing changes the bytes SHA256SUMS covers
#   (--force replaces the ad-hoc signature Go's linker adds on arm64):
#   codesign --force --sign "Developer ID Application: <name> (<team id>)" --options runtime --timestamp <binary>
#   notarytool takes a zip, not a .tar.gz: zip the binary, then
#   xcrun notarytool submit <zip> --keychain-profile <profile> --wait. A bare binary cannot be stapled.
