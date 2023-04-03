// Copyright 2020 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package remote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/stream"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"golang.org/x/sync/errgroup"
)

var acceptableManifestTypes = append(acceptableImageMediaTypes, acceptableIndexMediaTypes...)

// MultiWrite writes the given Images or ImageIndexes to the given refs, as
// efficiently as possible, by deduping shared layer blobs while uploading them
// in parallel.
//
// Current limitations:
// - Images cannot consist of stream.Layers.
func MultiWrite(todo map[name.Reference]Taggable, options ...Option) (rerr error) {
	o, err := makeOptions(options...)
	if err != nil {
		return err
	}
	if o.progress != nil {
		defer o.progress.Close(rerr)
	}
	p := newPusher(o)

	g, ctx := errgroup.WithContext(o.context)
	g.SetLimit(o.jobs)

	for ref, t := range todo {
		ref, t := ref, t
		g.Go(func() error {
			return p.Push(ctx, ref, t)
		})
	}

	return g.Wait()
}

type manifest interface {
	Taggable
	partial.Describable
}

// key is either v1.Hash or v1.Layer (for stream.Layer)
type workers struct {
	// map[v1.Hash|v1.Layer]*sync.Once
	onces sync.Map

	// map[v1.Hash|v1.Layer]error
	errors sync.Map
}

func nop() error {
	return nil
}

func (w *workers) Done(digest v1.Hash) error {
	v, ok := w.errors.Load(digest)
	if !ok || v == nil {
		return nil
	}
	return v.(error)
}

func (w *workers) Do(digest v1.Hash, f func() error) error {
	// We don't care if it was loaded or not because the sync.Once will do it for us.
	once, _ := w.onces.LoadOrStore(digest, &sync.Once{})

	once.(*sync.Once).Do(func() {
		w.errors.Store(digest, f())
	})

	return w.Done(digest)
}

func (w *workers) Stream(layer v1.Layer, f func() error) error {
	// We don't care if it was loaded or not because the sync.Once will do it for us.
	once, _ := w.onces.LoadOrStore(layer, &sync.Once{})

	once.(*sync.Once).Do(func() {
		w.errors.Store(layer, f())
	})

	v, ok := w.errors.Load(layer)
	if !ok || v == nil {
		return nil
	}

	return v.(error)
}

type Pusher struct {
	o *options

	// map[name.Repository]*repoWriter
	writers sync.Map
}

func NewPusher(options ...Option) (*Pusher, error) {
	o, err := makeOptions(options...)
	if err != nil {
		return nil, err
	}

	return newPusher(o), nil
}

func newPusher(o *options) *Pusher {
	return &Pusher{
		o: o,
	}
}

func (p *Pusher) writer(ctx context.Context, repo name.Repository, o *options) (*repoWriter, error) {
	v, _ := p.writers.LoadOrStore(repo, &repoWriter{
		repo: repo,
		o:    o,
	})
	rw := v.(*repoWriter)
	return rw, rw.init(ctx)
}

func (p *Pusher) Push(ctx context.Context, ref name.Reference, t Taggable) error {
	w, err := p.writer(ctx, ref.Context(), p.o)
	if err != nil {
		return err
	}
	return w.writeManifest(ctx, ref, t)
}

type repoWriter struct {
	repo name.Repository
	o    *options
	once sync.Once

	w *writer

	work *workers

	scopeLock sync.Mutex
	scopeSet  map[string]struct{}
	scopes    []string
}

// so you can use sync.Once but return an error
func onceErr(once *sync.Once, f func() error) (err error) {
	once.Do(func() {
		err = f()
	})
	return
}

// this will run once per repoWriter instance
func (rw *repoWriter) init(ctx context.Context) error {
	return onceErr(&rw.once, func() (err error) {
		scope := rw.repo.Scope(transport.PushScope)
		scopes := []string{scope}

		w, err := makeWriter(rw.repo, nil, rw.o)
		if err != nil {
			return err
		}

		rw.w = w
		rw.work = &workers{}
		rw.scopeSet = map[string]struct{}{
			scope: struct{}{},
		}
		rw.scopes = scopes

		return nil
	})
}

func (rw *repoWriter) maybeUpdateScopes(ml *MountableLayer) error {
	if ml.Reference.Context().String() == rw.repo.String() {
		return nil
	}
	if ml.Reference.Context().Registry.String() != rw.repo.Registry.String() {
		return nil
	}

	scope := ml.Reference.Scope(transport.PullScope)

	rw.scopeLock.Lock()
	defer rw.scopeLock.Unlock()

	if _, ok := rw.scopeSet[scope]; !ok {
		rw.scopeSet[scope] = struct{}{}
		rw.scopes = append(rw.scopes, scope)

		logs.Debug.Printf("Refreshing token to add scope %q", scope)
		wt, err := transport.NewWithContext(rw.o.context, rw.repo.Registry, rw.o.auth, rw.o.transport, rw.scopes)
		if err != nil {
			return err
		}
		rw.w.client = &http.Client{Transport: wt}
	}

	return nil
}

func (rw *repoWriter) writeDeps(ctx context.Context, m manifest) error {
	if img, ok := m.(v1.Image); ok {
		return rw.writeLayers(ctx, img)
	}

	if idx, ok := m.(v1.ImageIndex); ok {
		return rw.writeChildren(ctx, idx)
	}

	// This has no deps, not an error (e.g. something you want to just PUT).
	return nil
}

type describable struct {
	desc v1.Descriptor
}

func (d describable) Digest() (v1.Hash, error) {
	return d.desc.Digest, nil
}

func (d describable) Size() (int64, error) {
	return d.desc.Size, nil
}

func (d describable) MediaType() (types.MediaType, error) {
	return d.desc.MediaType, nil
}

type tagManifest struct {
	Taggable
	partial.Describable
}

func taggableToManifest(t Taggable) (manifest, error) {
	if m, ok := t.(manifest); ok {
		return m, nil
	}

	if d, ok := t.(*Descriptor); ok {
		if d.MediaType.IsIndex() {
			return d.ImageIndex()
		}

		if d.MediaType.IsImage() {
			return d.Image()
		}

		return tagManifest{t, describable{d.toDesc()}}, nil
	}

	desc := v1.Descriptor{
		// A reasonable default if Taggable doesn't implement MediaType.
		MediaType: types.DockerManifestSchema2,
	}

	b, err := t.RawManifest()
	if err != nil {
		return nil, err
	}

	if wmt, ok := t.(withMediaType); ok {
		desc.MediaType, err = wmt.MediaType()
		if err != nil {
			return nil, err
		}
	}

	desc.Digest, desc.Size, err = v1.SHA256(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	return tagManifest{t, describable{desc}}, nil
}

func (rw *repoWriter) writeManifest(ctx context.Context, ref name.Reference, t Taggable) error {
	m, err := taggableToManifest(t)
	if err != nil {
		return err
	}

	needDeps := true

	digest, err := m.Digest()
	if errors.Is(err, stream.ErrNotComputed) {
		if err := rw.writeDeps(ctx, m); err != nil {
			return err
		}

		needDeps = false

		digest, err = m.Digest()
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	// This may be a lazy child where we have no ref until digest is computed.
	if ref == nil {
		ref = rw.repo.Digest(digest.String())
	}

	// For tags, we want to do this check outside of our Work.Do closure because
	// we don't want to dedupe based on the manifest digest.
	_, byTag := ref.(name.Tag)
	if byTag {
		if exists, err := rw.manifestExists(ctx, ref, t); err != nil {
			return err
		} else if exists {
			return nil
		}
	}

	// The following work.Do will get deduped by digest, so it won't happen unless
	// this tag happens to be the first commitManifest to run for that digest.
	needPut := byTag

	if err := rw.work.Do(digest, func() error {
		if !byTag {
			if exists, err := rw.manifestExists(ctx, ref, t); err != nil {
				return err
			} else if exists {
				return nil
			}
		}

		if needDeps {
			if err := rw.writeDeps(ctx, m); err != nil {
				return err
			}
		}

		needPut = false
		return rw.commitManifest(ctx, ref, m)
	}); err != nil {
		return err
	}

	if !needPut {
		return nil
	}

	// Only runs for tags that got deduped by digest.
	return rw.commitManifest(ctx, ref, m)
}

func (rw *repoWriter) writeChildren(ctx context.Context, idx v1.ImageIndex) error {
	children, err := partial.Manifests(idx)
	if err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(rw.o.jobs)

	for _, child := range children {
		child := child
		if err := rw.writeChild(ctx, child, g); err != nil {
			return err
		}
	}

	return g.Wait()
}

func (rw *repoWriter) writeChild(ctx context.Context, child partial.Describable, g *errgroup.Group) error {
	switch child := child.(type) {
	case v1.ImageIndex:
		// For recursive index, we want to do a depth-first launching of goroutines
		// to avoid deadlocking.
		//
		// Note that this is rare, so the impact of this should be really small.
		return rw.writeManifest(ctx, nil, child)
	case v1.Image:
		g.Go(func() error {
			return rw.writeManifest(ctx, nil, child)
		})
	case v1.Layer:
		g.Go(func() error {
			return rw.writeLayer(ctx, child)
		})
	default:
		// This can't happen.
		return fmt.Errorf("Encountered unknown type: %T", child)
	}
	return nil
}

func (rw *repoWriter) manifestExists(ctx context.Context, ref name.Reference, t Taggable) (bool, error) {
	f := &fetcher{
		repo:    ref.Context(),
		Client:  rw.w.client,
		context: ctx,
	}

	m, err := taggableToManifest(t)
	if err != nil {
		return false, err
	}

	digest, err := m.Digest()
	if err != nil {
		// Possibly due to streaming layers.
		return false, nil
	}
	got, err := f.headManifest(ref, acceptableManifestTypes)
	if err != nil {
		var terr *transport.Error
		if errors.As(err, &terr) {
			if terr.StatusCode == http.StatusNotFound {
				return false, nil
			}
		}

		return false, err
	}

	// Mark that we saw this digest in the registry so we don't check again.
	rw.work.Do(got.Digest, nop)

	if digest != got.Digest {
		return false, nil
	}

	if tag, ok := ref.(name.Tag); ok {
		logs.Progress.Printf("existing manifest: %s@%s", tag.Identifier(), got.Digest)
	} else {
		logs.Progress.Print("existing manifest: ", got.Digest)
	}

	return true, nil
}

func (rw *repoWriter) commitManifest(ctx context.Context, ref name.Reference, m manifest) error {
	if rw.o.progress != nil {
		size, err := m.Size()
		if err != nil {
			return err
		}
		rw.o.progress.total(size)
	}

	return rw.w.commitManifest(ctx, m, ref)
}

func (rw *repoWriter) writeLayers(pctx context.Context, img v1.Image) error {
	ls, err := img.Layers()
	if err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(pctx)
	g.SetLimit(rw.o.jobs)

	for _, l := range ls {
		l := l

		g.Go(func() error {
			return rw.writeLayer(ctx, l)
		})
	}

	cl, err := partial.ConfigLayer(img)
	if errors.Is(err, stream.ErrNotComputed) {
		if err := g.Wait(); err != nil {
			return err
		}

		cl, err := partial.ConfigLayer(img)
		if err != nil {
			return err
		}

		return rw.writeLayer(pctx, cl)
	} else if err != nil {
		return err
	}

	g.Go(func() error {
		return rw.writeLayer(ctx, cl)
	})

	return g.Wait()
}

func (rw *repoWriter) writeLayer(ctx context.Context, l v1.Layer) (rerr error) {
	// Skip any non-distributable things.
	mt, err := l.MediaType()
	if err != nil {
		return err
	}
	if !mt.IsDistributable() && !rw.o.allowNondistributableArtifacts {
		return nil
	}

	if ml, ok := l.(*MountableLayer); ok {
		if err := rw.maybeUpdateScopes(ml); err != nil {
			return err
		}
	}

	digest, err := l.Digest()
	if err != nil {
		if errors.Is(err, stream.ErrNotComputed) {
			return rw.lazyWriteLayer(ctx, l)
		}
		return err
	}

	return rw.work.Do(digest, func() error {
		if rw.o.progress != nil {
			size, err := l.Size()
			if err != nil {
				return err
			}
			rw.o.progress.total(size)
		}
		return rw.w.uploadOne(ctx, l)
	})
}

func (rw *repoWriter) lazyWriteLayer(ctx context.Context, l v1.Layer) (rerr error) {
	return rw.work.Stream(l, func() error {
		if err := rw.w.uploadOne(ctx, l); err != nil {
			return err
		}

		// Mark this upload completed.
		digest, err := l.Digest()
		if err != nil {
			return err
		}

		rw.work.Do(digest, nop)

		if rw.o.progress != nil {
			size, err := l.Size()
			if err != nil {
				return err
			}
			rw.o.progress.total(size)
		}

		return nil
	})
}
