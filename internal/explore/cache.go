package explore

import (
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
)

// TODO: ctx for each
type Cache interface {
	Get(string) (*soci.Index, error)
	Put(string, *soci.Index) error
}

type ociCache struct {
	repo      name.Repository
	transport http.RoundTripper
}

func (o *ociCache) ref(key string) name.Reference {
	return o.repo.Tag(strings.Replace(key, ":", "-", 1) + ".soci")
}

func (o *ociCache) Get(key string) (*soci.Index, error) {
	img, err := remote.Image(o.ref(key), remote.WithTransport(o.transport))
	if err != nil {
		logs.Debug.Printf("cache pull: %v", err)
		return nil, err
	}
	return soci.FromImage(img)
}

func (o *ociCache) Put(key string, index *soci.Index) error {
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
	return path.Join("soci", strings.Replace(key, ":", "-", 1), "index.json")
}

func (g *gcsCache) object(key string) *storage.ObjectHandle {
	return g.bucket.Object(g.path(key))
}

func (g *gcsCache) Get(key string) (*soci.Index, error) {
	start := time.Now()
	defer func() {
		log.Printf("bucket.Get(%q) (%s)", key, time.Since(start))
	}()
	rc, err := g.object(key).NewReader(context.TODO())
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	index := &soci.Index{}
	if err := json.NewDecoder(rc).Decode(index); err != nil {
		return nil, err
	}
	return index, nil
}

func (g *gcsCache) Put(key string, index *soci.Index) error {
	start := time.Now()
	defer func() {
		log.Printf("bucket.Put(%q) (%s)", key, time.Since(start))
	}()
	w := g.object(key).NewWriter(context.TODO())
	if err := json.NewEncoder(w).Encode(index); err != nil {
		return err
	}
	return w.Close()
}

type dirCache struct {
	dir string
}

func (d *dirCache) file(key string) string {
	return filepath.Join(d.dir, strings.Replace(key, ":", "-", 1))
}

func (d *dirCache) Get(key string) (*soci.Index, error) {
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

func (d *dirCache) Put(key string, index *soci.Index) error {
	f, err := os.OpenFile(d.file(key), os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(index)
}

type memCache struct {
	sync.Mutex
	entryCap int
	maxSize  int64
	entries  []*headerEntry
}

type headerEntry struct {
	key    string
	index  *soci.Index
	size   int64
	access time.Time
}

func (m *memCache) Get(key string) (*soci.Index, error) {
	m.Lock()
	defer m.Unlock()

	for _, e := range m.entries {
		if e.key == key {
			e.access = time.Now()
			return e.index, nil
		}
	}
	return nil, io.EOF
}

func (m *memCache) Put(key string, index *soci.Index) error {
	m.Lock()
	defer m.Unlock()
	if index.Size() > m.maxSize {
		return nil
	}

	e := &headerEntry{
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

type multiCache struct {
	caches []Cache
}

func (m *multiCache) Get(key string) (*soci.Index, error) {
	for i, c := range m.caches {
		index, err := c.Get(key)
		if err == nil {
			// Backfill previous misses (usually in mem).
			for j := i - 1; j >= 0; j-- {
				cache := m.caches[j]
				logs.Debug.Printf("filling %q in %T", key, cache)
				if err := cache.Put(key, index); err != nil {
					logs.Debug.Printf("filling %q in %T = %v", key, cache, err)
				}
			}

			return index, err
		}
	}

	return nil, io.EOF
}

// TODO: concurrent?
func (m *multiCache) Put(key string, index *soci.Index) error {
	errs := []error{}
	for _, c := range m.caches {
		err := c.Put(key, index)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return Join(errs...)
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
