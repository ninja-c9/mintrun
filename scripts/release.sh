#!/usr/bin/env bash
# release.sh builds the release archives into dist/: per platform, a stripped -trimpath binary in
# dist/mintrun_<version>_<os>_<arch>/ with LICENSE and README.md, packed as a .tar.gz of that folder,
# then dist/SHA256SUMS. With SIGN_IDENTITY set it signs each darwin binary with that Developer ID,
# and with NOTARY_PROFILE set too it notarizes each one; otherwise it signs nothing (see the end).
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
	# Sign before packing, because signing changes the bytes SHA256SUMS covers (--force replaces the
	# ad-hoc signature Go's linker adds on arm64). notarytool takes a zip, and a bare binary cannot be stapled.
	if [[ $os == darwin && -n ${SIGN_IDENTITY:-} ]]; then
		codesign --force --sign "$SIGN_IDENTITY" --options runtime --timestamp "dist/$name/mintrun"
		codesign --verify --strict "dist/$name/mintrun"
		if [[ -n ${NOTARY_PROFILE:-} ]]; then
			(cd "dist/$name" && zip -q "../$name.zip" mintrun)
			xcrun notarytool submit "dist/$name.zip" --keychain-profile "$NOTARY_PROFILE" --wait | tee "dist/$name.notary"
			grep -q 'status: Accepted' "dist/$name.notary"
			rm "dist/$name.zip" "dist/$name.notary"
		fi
	fi
	cp LICENSE README.md "dist/$name/"
	# macOS tar would otherwise record the owner's user name, xattrs, and a ._ file per entry.
	COPYFILE_DISABLE=1 tar --owner=0 --group=0 --numeric-owner --no-xattrs -czf "dist/$name.tar.gz" -C dist "$name"
done

cd dist
if command -v sha256sum >/dev/null; then sha256sum mintrun_*.tar.gz; else shasum -a 256 mintrun_*.tar.gz; fi >SHA256SUMS
cat SHA256SUMS

# Left to the maintainer: signing the checksums, with gpg --armor --detach-sign dist/SHA256SUMS
# (writes SHA256SUMS.asc) or keyless cosign sign-blob --bundle dist/SHA256SUMS.sigstore.json dist/SHA256SUMS.
