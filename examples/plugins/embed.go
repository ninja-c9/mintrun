// Package plugins bundles the example plugins into the mintrun binary, so
// `mintrun plugin install <name>` installs one without a clone or a download:
// the build pins their content.
package plugins

import "embed"

// Catalog holds each example plugin under its directory name.
//
//go:embed bitwarden vercel postgres-jit
var Catalog embed.FS
