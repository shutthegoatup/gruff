// Package web embeds the portal's templates and static assets into the binary,
// so the process has no working-directory dependency and serves no third-party
// origins.
package web

import "embed"

// Files holds the HTML templates under template/ and the static assets under static/.
//
//go:embed template/*.html static/*.css static/*.svg static/fonts/*.woff2
var Files embed.FS
