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
	TOC   TOC
	bs    BlobSeeker
	dicts [][]byte

	cachedDict []byte
	cachedIdx  int

	sub *Tree
}

func dictFile(i int) string {
	return fmt.Sprintf("%d.dict", i)
}

const tocFile = "toc.json"

// TODO: Make things other than dict access lazy.
func (t *Tree) Dict(cp *Checkpointer) ([]byte, error) {
	if cp.index == 0 {
		return nil, nil
	}
	if t.sub == nil {
		if cp.index >= len(t.dicts) {
			return nil, fmt.Errorf("cannot access Dict[%d]", cp.index)
		}
		return t.dicts[cp.index], nil
	}

	if t.cachedIdx == cp.index {
		return t.cachedDict, nil
	}

	filename := dictFile(cp.index)
	rc, err := t.sub.Open(filename, t.bs)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	b, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}

	t.cachedIdx = cp.index
	t.cachedDict = b

	return b, nil
}

func (t *Tree) OpenFile(tf *TOCFile) (io.ReadCloser, error) {
	cp := t.Checkpoint(tf)
	dict, err := t.Dict(cp)
	if err != nil {
		return nil, err
	}

	return t.ExtractFile(context.TODO(), t.bs, cp, dict)
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

	from := cp.checkpoint
	from.Hist = dict

	logs.Debug.Printf("len(from.Hist) = %d", len(from.Hist))

	logs.Debug.Printf("Calling gzip.Continue")
	r, err := gzip.Continue(rc, 1<<22, from, nil)
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
	from := t.TOC.Checkpoints[0]
	discard := int64(0)
	index := 0
	for i, c := range t.TOC.Checkpoints {
		if c.Out > tf.Offset {
			discard = tf.Offset - from.Out
			break
		}
		if i == len(t.TOC.Checkpoints)-1 {
			discard = tf.Offset - c.Out
		}
		from = t.TOC.Checkpoints[i]
		index = i
	}
	start := from.In
	uend := tf.Offset + tf.Size

	logs.Debug.Printf("start=%d, uend=%d", start, uend)

	end := t.TOC.Csize
	for _, c := range t.TOC.Checkpoints {
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
	for _, f := range t.TOC.Files {
		if f.Name == name {
			return &f, nil
		}
	}

	return nil, fs.ErrNotExist
}

func NewTree(bs BlobSeeker, sub *Tree) (*Tree, error) {
	tree := &Tree{
		bs:        bs,
		sub:       sub,
		cachedIdx: -1,
	}

	if sub == nil {
		rc, err := bs.Reader(context.TODO(), 0, -1)
		if err != nil {
			return nil, err
		}
		defer rc.Close()

		return tree, tree.init(rc)
	}

	rc, err := sub.Open(tocFile, bs)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	toc := TOC{}
	if err := json.NewDecoder(rc).Decode(&toc); err != nil {
		return nil, err
	}
	tree.TOC = toc
	return tree, nil
}

func (t *Tree) init(rc io.Reader) error {
	zr, err := gzip.NewReader(rc)
	if err != nil {
		return err
	}
	tr := tar.NewReader(zr)

	t.dicts = [][]byte{}
	dictIndex := 0
	dictName := dictFile(dictIndex)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if header.Name == dictName {
			b, err := io.ReadAll(tr)
			if err != nil {
				return fmt.Errorf("%s ReadAll: %w", dictName, err)
			}
			t.dicts = append(t.dicts, b)
			dictIndex++
			dictName = dictFile(dictIndex)
		} else if header.Name == tocFile {
			toc := TOC{}
			if err := json.NewDecoder(tr).Decode(&toc); err != nil {
				return fmt.Errorf("Decode toc: %w", err)
			}
			t.TOC = toc
		}
	}
	return nil
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
	cw       *countWriter
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

func (i *TreeIndexer) Tree(bs BlobSeeker) (*Tree, error) {
	toc, err := i.TOC()
	if err != nil {
		return nil, err
	}

	tree := &Tree{
		TOC:       *toc,
		bs:        bs,
		cachedIdx: -1,
		dicts:     [][]byte{},
	}

	return tree, nil
}

func (i *TreeIndexer) Size() int64 {
	return i.cw.n
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
	if err := i.tw.Close(); err != nil {
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
		f := dictFile(len(i.toc.Checkpoints))

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
	cw := &countWriter{w, 0}

	i := &TreeIndexer{
		updates: updates,
		toc:     toc,
		in:      rc,
		zr:      zr,
		tr:      tar.NewReader(zr),
		tw:      tar.NewWriter(cw),
		cw:      cw,
		w:       w,
	}
	i.g.Go(i.processUpdates)

	updates <- &flate.Checkpoint{In: zr.CompressedCount()}

	return i, nil
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (n int, err error) {
	n, err = c.w.Write(p)
	c.n += int64(n)
	return
}
