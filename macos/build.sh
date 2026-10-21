#!/bin/sh
set -eu
DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
swiftc -O -framework AppKit -framework Foundation -framework SwiftUI "$DIR/MintrunMenuBar.swift" -o "$DIR/MintrunMenuBar"
echo "Built $DIR/MintrunMenuBar"
