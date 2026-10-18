#!/usr/bin/env bash
# verify.sh runs the AGENTS.md acceptance checks from the repository root, every one even after
# a failure, then prints a check | verdict table and exits 1 if any check failed.
set -euo pipefail
cd "$(dirname "$0")/.."

table=$(printf '%-24s | %s' check verdict)$'\n'
failed=0
record() {
	table+=$(printf '%-24s | %s' "$1" "$2")$'\n'
	[ "$2" = pass ] || failed=1
}

# Only the repo's own packages: gofmt walks into other sessions' worktrees under .claude/ (rule 17).
echo "== gofmt -s -l cmd internal examples"
if unformatted=$(gofmt -s -l cmd internal examples) && [ -z "$unformatted" ]; then
	record gofmt pass
else
	printf '%s\n' "$unformatted"
	record gofmt fail
fi

echo "== go vet ./..."
if go vet ./...; then record "go vet" pass; else record "go vet" fail; fi

echo "== go test -count=1 -coverprofile=coverage.out ./..."
trap 'rm -f coverage.out' EXIT
if go test -count=1 -coverprofile=coverage.out ./...; then record "go test" pass; else record "go test" fail; fi
# AGENTS.md: total statement coverage must stay above 90%. A missing total line fails too.
total=$(go tool cover -func=coverage.out | awk '$1 == "total:" { print $NF }') || total=""
if [ -n "$total" ] && awk -v t="${total%\%}" 'BEGIN { exit !(t > 90.0) }'; then
	record "coverage $total > 90%" pass
else
	record "coverage ${total:-unknown} > 90%" fail
fi

echo "== go build -trimpath -o mintrun ./cmd/mintrun && ./mintrun plugin list && ./mintrun -version"
if go build -trimpath -o mintrun ./cmd/mintrun && ./mintrun plugin list && ./mintrun -version; then
	record "build + smoke" pass
else
	record "build + smoke" fail
fi

printf '\n%s' "$table"
exit "$failed"
