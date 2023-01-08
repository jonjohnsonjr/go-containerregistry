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

	size int64 //cached
}

func (toc *TOC) Checkpoint(tf *TOCFile) *Checkpointer {
	from := toc.Checkpoints[0]
	discard := int64(0)
	index := 0
	for i, c := range toc.Checkpoints {
		if c.Out > tf.Offset {
			discard = tf.Offset - from.Out
			break
		}
		if i == len(toc.Checkpoints)-1 {
			discard = tf.Offset - c.Out
		}
		from = toc.Checkpoints[i]
		index = i
	}
	start := from.In
	uend := tf.Offset + tf.Size

	logs.Debug.Printf("start=%d, uend=%d", start, uend)

	end := toc.Csize
	for _, c := range toc.Checkpoints {
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
func (toc *TOC) Size() int64 {
	if toc.size != 0 {
		// TODO: do this while we generate it so we don't have to hit it twice.
		return toc.size
	}

	toc.size += 8 + 8 + 8

	for _, f := range toc.Files {
		toc.size += int64(1 + len(f.Name) + len(f.Linkname) + 8 + 8 + 8)
	}

	for _, c := range toc.Checkpoints {
		toc.size += int64(8 + 8 + 4 + 4 + len(c.Hist))
	}

	return toc.size
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

	cachedDict []byte
	cachedIdx  int

	sub Tree
}

func (t *tree) TOC() *TOC {
	return t.toc
}

func dictFile(i int) string {
	return fmt.Sprintf("%d.dict", i)
}

const tocFile = "toc.json"

func (t *tree) Open(name string) (io.ReadCloser, error) {
	logs.Debug.Printf("tree.Open(%q)", name)
	tf, err := t.sub.Locate(name)
	if err != nil {
		return nil, err
	}

	return ExtractTreeFile(context.TODO(), t.sub, t.bs, tf)
}

// TODO: Make things other than dict access lazy.
func (t *tree) Dict(cp *Checkpointer) ([]byte, error) {
	if cp.index == 0 {
		return nil, nil
	}

	if t.cachedIdx == cp.index {
		return t.cachedDict, nil
	}

	filename := dictFile(cp.index)
	rc, err := t.Open(filename)
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

func ExtractTreeFile(ctx context.Context, t Tree, bs BlobSeeker, tf *TOCFile) (io.ReadCloser, error) {
	cp := t.TOC().Checkpoint(tf)
	dict, err := t.Dict(cp)
	if err != nil {
		return nil, err
	}

	rc, err := bs.Reader(ctx, cp.start, cp.end)
	if err != nil {
		return nil, err
	}

	from := cp.checkpoint
	from.Hist = dict

	logs.Debug.Printf("Tree: ETF: Calling gzip.Continue")
	r, err := gzip.Continue(rc, 1<<22, from, nil)
	if err != nil {
		return nil, err
	}

	logs.Debug.Printf("Tree: Discarding %d bytes", cp.discard)
	if _, err := io.CopyN(io.Discard, r, cp.discard); err != nil {
		return nil, err
	}

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
		return newLeaf(bs, toc)
	}

	t := &tree{
		bs:        bs,
		sub:       sub,
		cachedIdx: -1,
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
	if err := json.NewDecoder(rc).Decode(toc); err != nil {
		return nil, err
	}
	t.toc = toc
	return t, nil
}

func newLeaf(bs BlobSeeker, toc *TOC) (*leaf, error) {
	t := &leaf{
		bs:  bs,
		toc: toc,
	}
	if toc == nil {
		return t, t.init()
	}
	return t, nil
}

func (t *leaf) init() error {
	t.dicts = [][]byte{}
	rc, err := t.bs.Reader(context.TODO(), 0, -1)
	if err != nil {
		return err
	}
	defer rc.Close()

	zr, err := gzip.NewReader(rc)
	if err != nil {
		return err
	}
	tr := tar.NewReader(zr)

	dictIndex := 0
	dictName := dictFile(dictIndex)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
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
			if t.toc != nil {
				break
			}

			t.toc = &TOC{}
			if err := json.NewDecoder(tr).Decode(t.toc); err != nil {
				return fmt.Errorf("Decode toc: %w", err)
			}
		}
	}

	return nil
}

type leaf struct {
	bs BlobSeeker

	dicts [][]byte
	toc   *TOC
}

func (t *leaf) Dict(cp *Checkpointer) ([]byte, error) {
	if t.dicts == nil {
		if err := t.init(); err != nil {
			return nil, err
		}
	}

	if cp.index >= len(t.dicts) {
		return nil, fmt.Errorf("Dict(%d) vs len(t.dicts) = %d", cp.index, len(t.dicts))
	}
	return t.dicts[cp.index], nil
}

func (t *leaf) Locate(name string) (*TOCFile, error) {
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
func (t *leaf) TOC() *TOC {
	return t.toc
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

func (i *TreeIndexer) Tree(bs BlobSeeker) (Tree, error) {
	toc, err := i.TOC()
	if err != nil {
		return nil, err
	}

	tree := &tree{
		toc:       toc,
		bs:        bs,
		cachedIdx: -1,
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
