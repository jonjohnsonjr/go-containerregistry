package soci

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/go-containerregistry/internal/compress/flate"
	"github.com/google/go-containerregistry/internal/compress/gzip"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"golang.org/x/sync/errgroup"
)

type TOCFile struct {
	// The tar stuff we care about for explore.ggcr.dev.
	Typeflag byte      `json:"typeflag,omitempty"`
	Name     string    `json:"name,omitempty"`
	Linkname string    `json:"linkname,omitempty"`
	Size     int64     `json:"size,omitempty"`
	Mode     int64     `json:"mode,omitempty"`
	ModTime  time.Time `json:"mod,omitempty"`

	// Our uncompressed offset so we can seek ahead.
	Offset int64
}

type Index struct {
	// Compressed size
	Csize int64 `json:"csize,omitempty"`

	// Uncompressed size
	Usize int64 `json:"usize,omitempty"`

	// Span size
	Ssize int64 `json:"ssize,omitempty"`

	size int64 // approximate binary size for caching purposes

	// TODO: Encode as json-lines so we can avoid buffering the entire TOC.
	//       Allow chunking into separate files with bloom filters per chunk.
	TOC []TOCFile `json:"toc,omitempty"`

	// TODO: Avoid depending on flate somehow.
	// TODO: Write each checkpoint as a separate file in a separate layer so
	//	 we can concurrently write TOC and Checkpoints and fetch them separately.
	// TODO: Store Checkpoint metadata separately from Hist.
	Checkpoints []flate.Checkpoint `json:"checkpoints,omitempty"`
}

func (i *Index) Size() int64 {
	if i.size != 0 {
		// TODO: do this while we generate it so we don't have to hit it twice.
		return i.size
	}

	i.size += 8 + 8 + 8

	for _, f := range i.TOC {
		i.size += int64(1 + len(f.Name) + len(f.Linkname) + 8 + 8 + 8)
	}

	for _, c := range i.Checkpoints {
		i.size += int64(8 + 8 + 4 + 4 + len(c.Hist))
	}

	return i.size
}

type Indexer struct {
	index    *Index
	updates  chan *flate.Checkpoint
	g        errgroup.Group
	in       io.ReadCloser
	zr       *gzip.Reader
	tr       *tar.Reader
	finished bool
}

func (i *Indexer) Next() (*tar.Header, error) {
	header, err := i.tr.Next()
	if errors.Is(err, io.EOF) {
		if !i.finished {
			close(i.updates)
			i.finished = true
		}
		return nil, err
	} else if err != nil {
		return nil, err
	}
	f := fromTar(header)
	f.Offset = i.zr.UncompressedCount()
	i.index.TOC = append(i.index.TOC, *f)
	return header, err
}

func (i *Indexer) Read(p []byte) (int, error) {
	return i.tr.Read(p)
}

func (i *Indexer) Close() error {
	// TODO: racey?
	return i.in.Close()
}

func (i *Indexer) Index() (*Index, error) {
	if err := i.g.Wait(); err != nil {
		return nil, err
	}

	if _, err := io.Copy(io.Discard, i.zr); err != nil {
		return nil, err
	}

	i.index.Csize = i.zr.CompressedCount()
	i.index.Usize = i.zr.UncompressedCount()

	return i.index, nil
}

func (i *Indexer) processUpdates() error {
	// TODO: Check for i.Writer and upload to caches.
	for update := range i.updates {
		u := update
		i.index.Checkpoints = append(i.index.Checkpoints, *u)
	}
	return nil
}

// TODO: Make it so we can resume this.
func NewIndexer(rc io.ReadCloser, span int64) (*Indexer, error) {
	index := &Index{
		TOC:         []TOCFile{},
		Checkpoints: []flate.Checkpoint{},
		Ssize:       span,
	}

	updates := make(chan *flate.Checkpoint)

	zr, err := gzip.NewReaderWithSpans(rc, span, updates)
	if err != nil {
		return nil, err
	}
	index.Checkpoints = append(index.Checkpoints, flate.Checkpoint{In: zr.CompressedCount()})

	i := &Indexer{
		updates: updates,
		index:   index,
		in:      rc,
		zr:      zr,
		tr:      tar.NewReader(zr),
	}
	i.g.Go(i.processUpdates)

	return i, nil
}

func fromTar(header *tar.Header) *TOCFile {
	return &TOCFile{
		Typeflag: header.Typeflag,
		Name:     header.Name,
		Linkname: header.Linkname,
		Size:     header.Size,
		Mode:     header.Mode,
		ModTime:  header.ModTime,
	}
}

// TODO: Streaming layers.
func ToImage(index *Index) (v1.Image, error) {
	b, err := json.Marshal(index)
	if err != nil {
		return nil, err
	}
	return crane.Image(map[string][]byte{
		"index.json": b,
	})
}

// TODO: This shouldn't be this hard lol.
func FromImage(img v1.Image) (*Index, error) {
	index := Index{}
	rc := mutate.Extract(img)
	defer rc.Close()
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		if hdr.Name == "index.json" {
			if err := json.NewDecoder(tr).Decode(&index); err != nil {
				return nil, err
			}
			return &index, nil
		}
	}

	return nil, fmt.Errorf("could not find index.json")
}
