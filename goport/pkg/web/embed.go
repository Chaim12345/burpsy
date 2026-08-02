package web

import (
	"embed"
)

//go:embed ui/index.html ui/style.css ui/app.js
var Assets embed.FS
