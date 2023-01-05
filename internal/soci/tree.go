package soci

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/google/go-containerregistry/internal/and"
	"github.com/google/go-containerregistry/internal/compress/flate"
	"github.com/google/go-containerregistry/internal/compress/gzip"
	"github.com/google/go-containerregistry/pkg/logs"
	"golang.org/x/sync/errgroup"
)

type TOC struct {
	// TODO: Move these so files/checkpoints can be streamingly parsed.
	Csize int64 `json:"csize,omitempty"`
	Usize int64 `json:"usize,omitempty"`
	Ssize int64 `json:"ssize,omitempty"`

	Files       []TOCFile          `json:"files,omitempty"`
	Checkpoints []flate.Checkpoint `json:"checkpoints,omitempty"`
}

type Checkpointer struct {
	checkpoint *flate.Checkpoint
	tf         *TOCFile
	index      int
	start      int64
	end        int64
	discard    int64
}

type Tree struct {
	toc   TOC
	bs    BlobSeeker
	dicts [][]byte

	sub *Tree
}

func (t *Tree) Dict(cp *Checkpointer) ([]byte, error) {
	if t.sub == nil {
		return t.dicts[cp.index], nil
	}

	filename := fmt.Sprintf("%d.dict", cp.index)
	rc, err := t.sub.Open(filename, t.bs)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	return io.ReadAll(rc)
}

func (t *Tree) Open(name string, bs BlobSeeker) (io.ReadCloser, error) {
	tf, err := t.Locate(name)
	if err != nil {
		return nil, err
	}
	cp := t.Checkpoint(tf)
	dict, err := t.Dict(cp)
	if err != nil {
		return nil, err
	}

	return t.ExtractFile(context.TODO(), bs, cp, dict)
}

func (t *Tree) ExtractFile(ctx context.Context, bs BlobSeeker, cp *Checkpointer, dict []byte) (io.ReadCloser, error) {
	rc, err := bs.Reader(ctx, cp.start, cp.end)
	if err != nil {
		return nil, err
	}

	logs.Debug.Printf("Calling gzip.Continue")
	r, err := gzip.Continue(rc, 1<<22, cp.checkpoint, nil)
	if err != nil {
		return nil, err
	}

	logs.Debug.Printf("Discarding %d bytes", cp.discard)
	if _, err := io.CopyN(io.Discard, r, cp.discard); err != nil {
		return nil, err
	}

	logs.Debug.Printf("Returning LimitedReader of size %d", cp.tf.Size)
	lr := io.LimitedReader{r, cp.tf.Size}
	return &and.ReadCloser{&lr, rc.Close}, nil
}

func (t *Tree) Checkpoint(tf *TOCFile) *Checkpointer {
	from := t.toc.Checkpoints[0]
	discard := int64(0)
	index := 0
	for i, c := range t.toc.Checkpoints {
		if c.Out > tf.Offset {
			discard = tf.Offset - from.Out
			break
		}
		if i == len(t.toc.Checkpoints)-1 {
			discard = tf.Offset - c.Out
		}
		from = t.toc.Checkpoints[i]
		index = i
	}
	start := from.In
	uend := tf.Offset + tf.Size

	logs.Debug.Printf("start=%d, uend=%d", start, uend)

	end := t.toc.Csize
	for _, c := range t.toc.Checkpoints {
		if c.Out > uend {
			end = c.In
			break
		}
	}

	return &Checkpointer{
		checkpoint: &from,
		tf:         tf,
		index:      index,
		start:      start,
		end:        end,
		discard:    discard,
	}
}

func (t *Tree) Locate(name string) (*TOCFile, error) {
	for _, f := range t.toc.Files {
		if f.Name == name {
			return &f, nil
		}
	}

	return nil, fs.ErrNotExist
}

func NewTree(bs BlobSeeker, sub *Tree) (*Tree, error) {
	tree := &Tree{
		bs:  bs,
		sub: sub,
	}

	if sub != nil {
		rc, err := sub.Open("toc.json", bs)
		if err != nil {
			return nil, err
		}
		toc := TOC{}
		if err := json.NewDecoder(rc).Decode(&toc); err != nil {
			return nil, err
		}
		tree.toc = toc
		return tree, nil
	}

	rc, err := bs.Reader(context.TODO(), 0, -1)
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(rc)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if header.Name == "toc.json" {
			toc := TOC{}
			if err := json.NewDecoder(tr).Decode(&toc); err != nil {
				return nil, err
			}
			tree.toc = toc
			return tree, nil
		}
	}

	return nil, io.EOF
}

type TreeIndexer struct {
	toc      *TOC
	updates  chan *flate.Checkpoint
	g        errgroup.Group
	in       io.ReadCloser
	zr       *gzip.Reader
	tr       *tar.Reader
	w        io.WriteCloser
	tw       *tar.Writer
	finished bool
	written  bool
}

func (i *TreeIndexer) Next() (*tar.Header, error) {
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
	i.toc.Files = append(i.toc.Files, *f)
	return header, err
}

func (i *TreeIndexer) Read(p []byte) (int, error) {
	return i.tr.Read(p)
}

func (i *TreeIndexer) Close() error {
	// TODO: racey?
	return i.in.Close()
}

func (i *TreeIndexer) TOC() (*TOC, error) {
	if i.written {
		return i.toc, nil
	}
	if err := i.g.Wait(); err != nil {
		return nil, err
	}

	if _, err := io.Copy(io.Discard, i.zr); err != nil {
		return nil, err
	}

	i.toc.Csize = i.zr.CompressedCount()
	i.toc.Usize = i.zr.UncompressedCount()

	b, err := json.Marshal(i.toc)
	if err != nil {
		return nil, err
	}
	if err := i.tw.WriteHeader(&tar.Header{
		Name: "toc.json",
		Size: int64(len(b)),
	}); err != nil {
		return nil, err
	}
	if _, err := i.tw.Write(b); err != nil {
		return nil, err
	}
	if err := i.w.Close(); err != nil {
		return nil, err
	}

	i.written = true

	return i.toc, nil
}

func (i *TreeIndexer) processUpdates() error {
	// TODO: Check for i.Writer and upload to caches.
	for update := range i.updates {
		u := update

		// TODO: Should updates be buffered so this doesn't block?
		b := u.Hist
		f := fmt.Sprintf("%d.dict", len(i.toc.Checkpoints))

		if err := i.tw.WriteHeader(&tar.Header{
			Name: f,
			Size: int64(len(b)),
		}); err != nil {
			return err
		}
		if _, err := i.tw.Write(b); err != nil {
			return err
		}

		u.Hist = nil
		i.toc.Checkpoints = append(i.toc.Checkpoints, *u)
	}
	return nil
}

// TODO: Make it so we can resume this.
func NewTreeIndexer(rc io.ReadCloser, w io.WriteCloser, span int64) (*TreeIndexer, error) {
	updates := make(chan *flate.Checkpoint)

	toc := &TOC{
		Files:       []TOCFile{},
		Checkpoints: []flate.Checkpoint{},
		Ssize:       span,
	}

	zr, err := gzip.NewReaderWithSpans(rc, span, updates)
	if err != nil {
		return nil, err
	}
	toc.Checkpoints = append(toc.Checkpoints, flate.Checkpoint{In: zr.CompressedCount()})

	i := &TreeIndexer{
		updates: updates,
		toc:     toc,
		in:      rc,
		zr:      zr,
		tr:      tar.NewReader(zr),
		tw:      tar.NewWriter(w),
		w:       w,
	}
	i.g.Go(i.processUpdates)

	return i, nil
}
