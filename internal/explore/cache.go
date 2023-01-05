package explore

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"github.com/google/go-containerregistry/internal/soci"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/klauspost/compress/zstd"
)

type Cache interface {
	Get(context.Context, string) (*soci.Index, error)
	Put(context.Context, string, *soci.Index) error
}

// Streaming cache.
type cache interface {
	Cache
	Size(context.Context, string) (int64, error)
	Writer(context.Context, string) (io.WriteCloser, error)
	Reader(context.Context, string) (io.ReadCloser, error)
	RangeReader(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error)
}

type ociCache struct {
	repo      name.Repository
	transport http.RoundTripper
}

func (m *ociCache) Writer(ctx context.Context, key string) (io.WriteCloser, error) {
	panic("ociCache.Writer")
}

func (m *ociCache) Reader(ctx context.Context, key string) (io.ReadCloser, error) {
	panic("ociCache.Reader")
}

func (m *ociCache) RangeReader(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	panic("ociCache.RangeReader")
}

func (m *ociCache) Size(ctx context.Context, key string) (int64, error) {
	panic("ociCache.Size")
}

func (o *ociCache) ref(key string) name.Reference {
	return o.repo.Tag(strings.Replace(key, ":", "-", 1) + ".soci")
}

func (o *ociCache) Get(ctx context.Context, key string) (*soci.Index, error) {
	img, err := remote.Image(o.ref(key), remote.WithTransport(o.transport))
	if err != nil {
		logs.Debug.Printf("cache pull: %v", err)
		return nil, err
	}
	return soci.FromImage(img)
}

func (o *ociCache) Put(ctx context.Context, key string, index *soci.Index) error {
	img, err := soci.ToImage(index)
	if err != nil {
		return err
	}
	return remote.Write(o.ref(key), img, remote.WithTransport(o.transport))
}

// TODO: We can separate the TOC from the checkpoints to avoid some buffering.
type gcsCache struct {
	client *storage.Client
	bucket *storage.BucketHandle
}

func (g *gcsCache) path(key string) string {
	return path.Join("soci", strings.Replace(key, ":", "-", 1), "index.json.zstd")
}

func (g *gcsCache) object(key string) *storage.ObjectHandle {
	return g.bucket.Object(g.path(key))
}

// TODO: Use lifecycle with bumping timestamps to evict old data.
func (g *gcsCache) Get(ctx context.Context, key string) (*soci.Index, error) {
	start := time.Now()
	defer func() {
		log.Printf("bucket.Get(%q) (%s)", key, time.Since(start))
	}()
	rc, err := g.object(key).NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	dec, err := zstd.NewReader(rc)
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	index := &soci.Index{}
	if err := json.NewDecoder(dec).Decode(index); err != nil {
		return nil, err
	}
	return index, nil
}

func (g *gcsCache) Put(ctx context.Context, key string, index *soci.Index) error {
	start := time.Now()
	defer func() {
		log.Printf("bucket.Put(%q) (%s)", key, time.Since(start))
	}()
	w := g.object(key).NewWriter(ctx)
	enc, err := zstd.NewWriter(w)
	if err != nil {
		logs.Debug.Printf("zstd.NewWriter() = %v", err)
		return err
	}
	if err := json.NewEncoder(enc).Encode(index); err != nil {
		logs.Debug.Printf("Encode() = %v", err)
		enc.Close()
		return err
	}
	if err := enc.Close(); err != nil {
		logs.Debug.Printf("enc.Close() = %v", err)
		return err
	}
	return w.Close()
}

func (g *gcsCache) Writer(ctx context.Context, key string) (io.WriteCloser, error) {
	return g.object(key).NewWriter(ctx), nil
}

func (g *gcsCache) Reader(ctx context.Context, key string) (io.ReadCloser, error) {
	return g.object(key).NewReader(ctx)
}

func (g *gcsCache) RangeReader(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	return g.object(key).NewRangeReader(ctx, offset, length)
}

func (g *gcsCache) Size(ctx context.Context, key string) (int64, error) {
	attrs, err := g.object(key).Attrs(ctx)
	if err != nil {
		return -1, err
	}
	return attrs.Size, nil
}

type dirCache struct {
	dir string
}

func (d *dirCache) file(key string) string {
	return filepath.Join(d.dir, strings.Replace(key, ":", "-", 1))
}

func (d *dirCache) Get(ctx context.Context, key string) (*soci.Index, error) {
	f, err := os.Open(d.file(key))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	index := &soci.Index{}
	if err := json.NewDecoder(f).Decode(index); err != nil {
		return nil, err
	}
	return index, nil
}

func (d *dirCache) Put(ctx context.Context, key string, index *soci.Index) error {
	f, err := os.OpenFile(d.file(key), os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(index)
}

func (d *dirCache) Writer(ctx context.Context, key string) (io.WriteCloser, error) {
	return os.OpenFile(d.file(key), os.O_RDWR|os.O_CREATE, 0755)
}

func (d *dirCache) Reader(ctx context.Context, key string) (io.ReadCloser, error) {
	return os.Open(d.file(key))
}

func (d *dirCache) RangeReader(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	f, err := os.Open(d.file(key))
	if err != nil {
		return nil, err
	}
	return io.NopCloser(io.NewSectionReader(f, offset, length)), nil
}

func (d *dirCache) Size(ctx context.Context, key string) (int64, error) {
	stat, err := os.Stat(d.file(key))
	if err != nil {
		return -1, err
	}
	return stat.Size(), nil
}

type memCache struct {
	sync.Mutex
	entryCap int
	maxSize  int64
	entries  []*cacheEntry
}

type cacheEntry struct {
	key    string
	index  *soci.Index
	buffer []byte
	size   int64
	access time.Time
}

func (m *memCache) get(ctx context.Context, key string) (*cacheEntry, error) {
	m.Lock()
	defer m.Unlock()

	for _, e := range m.entries {
		if e.key == key {
			e.access = time.Now()
			return e, nil
		}
	}
	return nil, io.EOF
}

func (m *memCache) Get(ctx context.Context, key string) (*soci.Index, error) {
	e, err := m.get(ctx, key)
	if err != nil {
		return nil, err
	}

	return e.index, nil
}

func (m *memCache) Put(ctx context.Context, key string, index *soci.Index) error {
	m.Lock()
	defer m.Unlock()
	if index.Size() > m.maxSize {
		return nil
	}

	e := &cacheEntry{
		key:    key,
		index:  index,
		size:   index.Size(),
		access: time.Now(),
	}

	if len(m.entries) >= m.entryCap {
		min, idx := e.access, -1
		for i, e := range m.entries {
			if e.access.Before(min) {
				min = e.access
				idx = i
			}
		}
		m.entries[idx] = e
		return nil
	}

	m.entries = append(m.entries, e)
	return nil
}

func (m *memCache) New(ctx context.Context, key string) *cacheEntry {
	e := &cacheEntry{
		key:    key,
		access: time.Now(),
	}
	if len(m.entries) >= m.entryCap {
		min, idx := e.access, -1
		for i, e := range m.entries {
			if e.access.Before(min) {
				min = e.access
				idx = i
			}
		}
		m.entries[idx] = e
	} else {
		m.entries = append(m.entries, e)
	}
	return e
}

type memWriter struct {
	entry *cacheEntry
	buf   *bytes.Buffer
}

func (w *memWriter) Write(p []byte) (n int, err error) {
	return w.buf.Write(p)
}

func (w *memWriter) Close() (err error) {
	w.entry.buffer = w.buf.Bytes()
	return nil
}

func (m *memCache) Writer(ctx context.Context, key string) (io.WriteCloser, error) {
	e := m.New(ctx, key)
	mw := &memWriter{entry: e}
	return mw, nil
}

func (m *memCache) Reader(ctx context.Context, key string) (io.ReadCloser, error) {
	e, err := m.get(ctx, key)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(e.buffer)), nil
}

func (m *memCache) RangeReader(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error) {
	e, err := m.get(ctx, key)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(e.buffer[offset : offset+length])), nil
}

func (m *memCache) Size(ctx context.Context, key string) (int64, error) {
	e, err := m.get(ctx, key)
	if err != nil {
		return -1, err
	}
	return int64(len(e.buffer)), nil
}

type multiCache struct {
	caches []cache
}

func (m *multiCache) Get(ctx context.Context, key string) (*soci.Index, error) {
	for i, c := range m.caches {
		index, err := c.Get(ctx, key)
		if err == nil {
			// Backfill previous misses (usually in mem).
			for j := i - 1; j >= 0; j-- {
				cache := m.caches[j]
				logs.Debug.Printf("filling %q in %T", key, cache)
				if err := cache.Put(ctx, key, index); err != nil {
					logs.Debug.Printf("filling %q in %T = %v", key, cache, err)
				}
			}

			return index, err
		} else {
			logs.Debug.Printf("multi[%T].Get(%q) = %v", c, key, err)
		}
	}

	return nil, io.EOF
}

// TODO: concurrent?
func (m *multiCache) Put(ctx context.Context, key string, index *soci.Index) error {
	errs := []error{}
	for _, c := range m.caches {
		err := c.Put(ctx, key, index)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return Join(errs...)
}

func (m *multiCache) Writer(ctx context.Context, key string) (io.WriteCloser, error) {
	writers := []io.WriteCloser{}
	for _, c := range m.caches {
		w, err := c.Writer(ctx, key)
		if err != nil {
			return nil, err
		}
		writers = append(writers, w)
	}
	return MultiWriter(writers...), nil
}

type multiWriter struct {
	writers []io.WriteCloser
}

func (t *multiWriter) Write(p []byte) (n int, err error) {
	for _, w := range t.writers {
		n, err = w.Write(p)
		if err != nil {
			return
		}
		if n != len(p) {
			err = io.ErrShortWrite
			return
		}
	}
	return len(p), nil
}

func (t *multiWriter) Close() error {
	errs := []error{}
	for _, w := range t.writers {
		if err := w.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	return Join(errs...)
}

func MultiWriter(writers ...io.WriteCloser) io.WriteCloser {
	allWriters := make([]io.WriteCloser, 0, len(writers))
	for _, w := range writers {
		if mw, ok := w.(*multiWriter); ok {
			allWriters = append(allWriters, mw.writers...)
		} else {
			allWriters = append(allWriters, w)
		}
	}
	return &multiWriter{allWriters}
}

// TODO: 1.20 errors.Join
func Join(errs ...error) error {
	n := 0
	for _, err := range errs {
		if err != nil {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	e := &joinError{
		errs: make([]error, 0, n),
	}
	for _, err := range errs {
		if err != nil {
			e.errs = append(e.errs, err)
		}
	}
	return e
}

type joinError struct {
	errs []error
}

func (e *joinError) Error() string {
	var b []byte
	for i, err := range e.errs {
		if i > 0 {
			b = append(b, '\n')
		}
		b = append(b, err.Error()...)
	}
	return string(b)
}

func (e *joinError) Unwrap() []error {
	return e.errs
}
