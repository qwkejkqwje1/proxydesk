package web

import (
	"embed"
	"io/fs"
)

//go:embed dist/*
var distEmbedFS embed.FS

func DistFS() (fs.FS, error) {
	return fs.Sub(distEmbedFS, "dist")
}
