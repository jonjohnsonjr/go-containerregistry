package soci

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"strings"
	"time"

	"github.com/google/go-containerregistry/internal/and"
	"github.com/google/go-containerregistry/internal/compress/flate"
	"github.com/google/go-containerregistry/internal/compress/gzip"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/klauspost/compress/zstd"
)

type TOC struct {
	// TODO: Move these so files/checkpoints can be streamingly parsed.
	// metadata.json?
	Csize int64 `json:"csize,omitempty"`
	Usize int64 `json:"usize,omitempty"`
	Ssize int64 `json:"ssize,omitempty"`

	// TODO: Files as jsonlines in separate file.
	Files []TOCFile `json:"files,omitempty"`

	// TODO: Checkpoints as jsonlines in separate file.
	Checkpoints []*flate.Checkpoint `json:"checkpoints,omitempty"`

	ArchiveSize int64 `json:"asize,omitempty"`
	Size        int64 `json:"size,omitempty"`

	Type string `json:"type,omitempty"`
}

func (toc *TOC) Checkpoint(tf *TOCFile) *Checkpointer {
	if len(toc.Checkpoints) == 0 {
		return &Checkpointer{
			checkpoint: &flate.Checkpoint{
				Empty: true,
			},
			tf:    tf,
			start: tf.Offset,
			end:   tf.Offset + tf.Size,
		}
	}
	from := toc.Checkpoints[0]
	discard := int64(0)
	index := 0
	for i, c := range toc.Checkpoints {
		if c.BytesWritten() > tf.Offset {
			discard = tf.Offset - from.BytesWritten()
			break
		}
		if i == len(toc.Checkpoints)-1 {
			discard = tf.Offset - c.BytesWritten()
		}
		from = toc.Checkpoints[i]
		index = i
	}
	start := from.BytesRead()
	uend := tf.Offset + tf.Size

	logs.Debug.Printf("start=%d, uend=%d", start, uend)

	end := toc.Csize
	for _, c := range toc.Checkpoints {
		if c.BytesWritten() > uend {
			end = c.BytesRead()
			break
		}
	}

	return &Checkpointer{
		checkpoint: from,
		tf:         tf,
		index:      index,
		start:      start,
		end:        end,
		discard:    discard,
	}
}

type Checkpointer struct {
	checkpoint *flate.Checkpoint
	tf         *TOCFile
	index      int
	start      int64
	end        int64
	discard    int64
}

type Tree interface {
	Dict(cp *Checkpointer) ([]byte, error)
	Locate(name string) (*TOCFile, error)
	TOC() *TOC
}

type tree struct {
	toc *TOC

	// BlobSeeker for _index_ files.
	bs BlobSeeker

	sub Tree
}

func (t *tree) TOC() *TOC {
	return t.toc
}

func dictFile(i int) string {
	return fmt.Sprintf("%05d.dict", i)
}

const tocFile = "toc.json"

func (t *tree) Open(name string) (io.ReadCloser, error) {
	logs.Debug.Printf("tree.Open(%q)", name)
	start := time.Now()
	defer func() {
		log.Printf("tree.Open(%q) (%s)", name, time.Since(start))
	}()
	tf, err := t.sub.Locate(name)
	if err != nil {
		return nil, err
	}

	return ExtractTreeFile(context.TODO(), t.sub, t.bs, tf)
}

// TODO: Make things other than dict access lazy.
func (t *tree) Dict(cp *Checkpointer) ([]byte, error) {
	if cp.index == 0 || cp.checkpoint.IsEmpty() {
		return nil, nil
	}
	if hist := cp.checkpoint.History(); hist != nil {
		return hist, nil
	}

	filename := dictFile(cp.index)
	rc, err := t.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("Open(%q): %w", filename, err)
	}
	defer rc.Close()

	b, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("Open(%q).ReadAll(): %w", filename, err)
	}
	cp.checkpoint.SetHistory(b)

	return b, nil
}

func ExtractTreeFile(ctx context.Context, t Tree, bs BlobSeeker, tf *TOCFile) (io.ReadCloser, error) {
	start := time.Now()
	defer func() {
		log.Printf("ExtractTreeFile(%q) (%s)", tf.Name, time.Since(start))
	}()
	if tf.Size == 0 {
		return io.NopCloser(&io.LimitedReader{N: 0}), nil
	}
	cp := t.TOC().Checkpoint(tf)
	dict, err := t.Dict(cp)
	if err != nil {
		return nil, fmt.Errorf("Dict(): %w", err)
	}

	rc, err := bs.Reader(ctx, cp.start, cp.end)
	if err != nil {
		return nil, fmt.Errorf("Reader(): %w", err)
	}

	from := cp.checkpoint
	from.SetHistory(dict)

	kind := t.TOC().Type
	if kind == "tar" {
		logs.Debug.Printf("Type = tar")
		logs.Debug.Printf("Tree: Returning LimitedReader of size %d", cp.tf.Size)
		lr := io.LimitedReader{rc, cp.tf.Size}
		return &and.ReadCloser{&lr, rc.Close}, nil
	}

	var r io.ReadCloser
	if kind == "tar+zstd" {
		// TODO: zstd.Continue
		logs.Debug.Printf("Tree: ETF: zstd+tar")
		zr, err := zstd.NewReader(rc)
		if err != nil {
			return nil, err
		}
		r = zr.IOReadCloser()
	} else {
		logs.Debug.Printf("Tree: ETF: Calling gzip.Continue")
		r, err = gzip.Continue(rc, 1<<22, from, nil)
		if err != nil {
			return nil, err
		}
	}

	start2 := time.Now()
	logs.Debug.Printf("Tree: Discarding %d bytes", cp.discard)
	n, err := io.CopyN(io.Discard, r, cp.discard)
	if err != nil {
		return nil, err
	}
	log.Printf("Discarded %d bytes before %q (%s)", n, tf.Name, time.Since(start2))

	logs.Debug.Printf("Tree: Returning LimitedReader of size %d", cp.tf.Size)
	lr := io.LimitedReader{r, cp.tf.Size}
	return &and.ReadCloser{&lr, rc.Close}, nil
}

func (t *tree) Locate(name string) (*TOCFile, error) {
	for _, f := range t.toc.Files {
		if f.Name == name {
			return &f, nil
		}
	}

	return nil, fs.ErrNotExist
}

func NewTree(bs BlobSeeker, toc *TOC, sub Tree) (Tree, error) {
	if sub == nil {
		return NewLeaf(bs, toc)
	}

	t := &tree{
		bs:  bs,
		sub: sub,
	}

	if toc != nil {
		t.toc = toc
		return t, nil
	}

	rc, err := t.Open(tocFile)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	toc = &TOC{}
	dec := json.NewDecoder(rc)
	if err := dec.Decode(toc); err != nil {
		return nil, err
	}
	toc.Size = dec.InputOffset()
	t.toc = toc
	return t, nil
}

func NewLeaf(bs BlobSeeker, toc *TOC) (*Leaf, error) {
	t := &Leaf{
		bs:  bs,
		toc: toc,
	}
	if toc == nil {
		return t, t.init()
	}
	return t, nil
}

func (t *Leaf) init() error {
	start := time.Now()
	defer func() {
		log.Printf("tree.init() (%s)", time.Since(start))
	}()
	t.dicts = map[string][]byte{}
	rc, err := t.bs.Reader(context.TODO(), 0, -1)
	if err != nil {
		return fmt.Errorf("Reader(): %w", err)
	}
	defer rc.Close()

	zr, err := gzip.NewReader(rc)
	if err != nil {
		return err
	}
	tr := tar.NewReader(zr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		if strings.HasSuffix(header.Name, ".dict") {
			b, err := io.ReadAll(tr)
			if err != nil {
				return fmt.Errorf("%s ReadAll: %w", header.Name, err)
			}
			t.dicts[header.Name] = b
		} else if header.Name == tocFile {
			if t.toc != nil {
				break
			}

			t.toc = &TOC{}
			if err := json.NewDecoder(tr).Decode(t.toc); err != nil {
				return fmt.Errorf("Decode toc: %w", err)
			}
			t.toc.Size = header.Size
			t.toc.ArchiveSize = zr.UncompressedCount()
		}
	}

	return nil
}

type Leaf struct {
	bs BlobSeeker

	dicts map[string][]byte
	toc   *TOC
}

func (t *Leaf) Dict(cp *Checkpointer) ([]byte, error) {
	if cp.checkpoint.IsEmpty() {
		return nil, nil
	}
	if hist := cp.checkpoint.History(); hist != nil {
		return hist, nil
	}
	if t.dicts == nil {
		if err := t.init(); err != nil {
			return nil, fmt.Errorf("init(): %w", err)
		}
	}

	dictName := dictFile(cp.index)
	hist, ok := t.dicts[dictName]
	if !ok {
		return nil, fmt.Errorf("Dict(%d), %q not found", cp.index, dictName)
	}

	cp.checkpoint.SetHistory(hist)

	return hist, nil
}

func (t *Leaf) Locate(name string) (*TOCFile, error) {
	if t.toc == nil {
		if err := t.init(); err != nil {
			return nil, err
		}
	}
	for _, f := range t.toc.Files {
		if f.Name == name {
			return &f, nil
		}
	}

	return nil, fs.ErrNotExist
}

func (t *Leaf) TOC() *TOC {
	return t.toc
}
