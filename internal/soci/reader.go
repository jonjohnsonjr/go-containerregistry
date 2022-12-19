package soci

import (
	"context"
	"io"
	"time"

	"github.com/opencontainers/go-digest"
)

type Ztoc struct {
	Version                 string
	BuildToolIdentifier     string
	CompressedArchiveSize   int64
	UncompressedArchiveSize int64
	TOC                     TOC
	CompressionInfo         CompressionInfo
}

type TOC struct {
	Metadata []FileMetadata
}

// TODO: make this tar headers?
type FileMetadata struct {
	Name               string
	Type               string
	UncompressedOffset int64
	UncompressedSize   int64
	Linkname           string // Target name of link (valid for TypeLink or TypeSymlink)
	Mode               int64  // Permission and mode bits
	UID                int    // User ID of owner
	GID                int    // Group ID of owner
	Uname              string // User name of owner
	Gname              string // Group name of owner

	ModTime  time.Time // Modification time
	Devmajor int64     // Major device number (valid for TypeChar or TypeBlock)
	Devminor int64     // Minor device number (valid for TypeChar or TypeBlock)

	Xattrs map[string]string
}

type CompressionInfo struct {
	MaxSpanID   int32
	SpanDigests []digest.Digest
	Checkpoints []byte
}

// TODO: Checkpoints should not be a []byte.
type FileExtractConfig struct {
	UncompressedSize      int64
	UncompressedOffset    int64
	Checkpoints           []byte
	CompressedArchiveSize int64
	MaxSpanID             int32
}

// Should generate an HTTP GET with Range of [file start, file end].
//
// SectionReader will need to:
//
//	Know total size of file.
//	Know redirected blob URL.
//	Know how to re-fetch the blob if we time out.
//
// Reader will need to:
//
//	Inflate what it gets back from SectionReader.
//	Return as much as will fit in the provided buffer.
//	Cache the rest of it and potentially read more.
//	Background routine that is staying ahead of the consumer writing to buffer as much as we can.
func ExtractFile(ctx context.Context, r *io.SectionReader, config *FileExtractConfig) (io.ReadCloser, error) {
	return nil, nil
}
