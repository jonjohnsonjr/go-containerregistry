package soci

import "github.com/google/go-containerregistry/internal/compress/flate"

type TOCFile struct {
	// The tar stuff we care about for explore.ggcr.dev.
	Typeflag byte
	Name     string
	Linkname string
	Size     int64
	Mode     int64

	// Our uncompressed offset so we can seek ahead.
	Offset int64
}

type Index struct {
	Csize int64
	Usize int64
	TOC   []TOCFile
	// TODO: Avoid depending on flate somehow.
	Checkpoints []flate.Checkpoint
}
