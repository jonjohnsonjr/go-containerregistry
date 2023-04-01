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

	"github.com/google/go-containerregistry/pkg/authn"
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
	o, err := makeOptions(nil, options...)
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

type workers struct {
	// map[v1.Hash]*sync.Once
	onces sync.Map

	// map[v1.Hash]error
	errors sync.Map
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

type Pusher struct {
	o *options

	// map[name.Repository]*repoWriter
	writers sync.Map
}

func NewPusher(keychain authn.Keychain, options ...Option) (*Pusher, error) {
	o, err := makeOptions(nil, options...)
	if err != nil {
		return nil, err
	}
	o.keychain = keychain
	o.auth = nil

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
	return w.write(ctx, ref, t)
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

	roots     errgroup.Group
	manifests errgroup.Group
	blobs     errgroup.Group
}

// so you can use sync.Once but return an error
func onceErr(once *sync.Once, f func() error) (err error) {
	once.Do(func() {
		err = f()
	})
	return
}

// this will run once per repoWriter instance
func (r *repoWriter) init(ctx context.Context) error {
	return onceErr(&r.once, func() (err error) {
		scope := r.repo.Scope(transport.PushScope)
		scopes := []string{scope}

		auth := r.o.auth
		if r.o.keychain != nil {
			auth, err = r.o.keychain.Resolve(r.repo)
			if err != nil {
				return err
			}
		}

		rt, err := transport.NewWithContext(ctx, r.repo.Registry, auth, r.o.transport, scopes)
		if err != nil {
			return err
		}

		r.w = &writer{
			repo:      r.repo,
			client:    &http.Client{Transport: rt},
			progress:  r.o.progress,
			backoff:   r.o.retryBackoff,
			predicate: r.o.retryPredicate,
		}
		r.work = &workers{}
		r.scopeSet = map[string]struct{}{
			scope: struct{}{},
		}
		r.scopes = scopes

		r.blobs.SetLimit(r.o.jobs)
		r.manifests.SetLimit(r.o.jobs)

		// Separate from manifests so we don't block our children.
		r.roots.SetLimit(r.o.jobs)

		return nil
	})
}

func (r *repoWriter) maybeUpdateScopes(ml *MountableLayer) error {
	if ml.Reference.Context().String() == r.repo.String() {
		return nil
	}
	if ml.Reference.Context().Registry.String() != r.repo.Registry.String() {
		return nil
	}

	scope := ml.Reference.Scope(transport.PullScope)

	r.scopeLock.Lock()
	defer r.scopeLock.Unlock()

	if _, ok := r.scopeSet[scope]; !ok {
		r.scopeSet[scope] = struct{}{}
		r.scopes = append(r.scopes, scope)

		logs.Debug.Printf("Refreshing token to add scope %q", scope)
		wt, err := transport.NewWithContext(r.o.context, r.repo.Registry, r.o.auth, r.o.transport, r.scopes)
		if err != nil {
			return err
		}
		r.w.client = &http.Client{Transport: wt}
	}

	return nil
}

func (r *repoWriter) write(ctx context.Context, ref name.Reference, t Taggable) error {
	// Make it so you can just pass the results of remote.Get into this.
	if desc, ok := t.(*Descriptor); ok {
		if desc.MediaType.IsIndex() {
			idx, err := desc.ImageIndex()
			if err != nil {
				return err
			}
			t = idx
		} else {
			img, err := desc.Image()
			if err != nil {
				return err
			}
			t = img

		}
	}
	if exists, err := r.manifestExists(ctx, ref, t); err != nil {
		return err
	} else if exists {
		return nil
	}

	return r.writeManifest(ctx, ref, t)
}

func (r *repoWriter) writeDeps(ctx context.Context, m manifest) error {
	if img, ok := m.(v1.Image); ok {
		return r.writeLayers(ctx, img)
	}

	if idx, ok := m.(v1.ImageIndex); ok {
		return r.writeChildren(ctx, idx)
	}

	// This has no deps, not an error (e.g. something you want to just PUT).
	return nil
}

func (r *repoWriter) lazyWriteManifest(ctx context.Context, ref name.Reference, m manifest) error {
	if err := r.writeDeps(ctx, m); err != nil {
		return err
	}
	digest, err := m.Digest()
	if err != nil {
		return err
	}
	firstPut := false
	if err := r.work.Do(digest, func() error {
		firstPut = true
		return r.commitManifest(ctx, ref, m)
	}); err != nil {
		return err
	}

	if firstPut {
		return nil
	}

	return r.commitManifest(ctx, ref, m)
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
		return tagManifest{t, partial.FromDescriptor(d.toDesc())}, nil
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

	return tagManifest{t, partial.FromDescriptor(desc)}, nil
}

func (r *repoWriter) writeManifest(ctx context.Context, ref name.Reference, t Taggable) error {
	m, err := taggableToManifest(t)
	if err != nil {
		return err
	}

	digest, err := m.Digest()
	if errors.Is(err, stream.ErrNotComputed) {
		return r.lazyWriteManifest(ctx, ref, m)
	} else if err != nil {
		return err
	}

	// The first time we work.Do this digest, we want to PUT the manifest as well so that
	// if this is a child of an index, we can depend on the digest to know that someone PUT
	// it already for us.
	//
	// If we happen to be the first manifest with this digest, we want to do a PUT with our
	// tag (if we have one), but not do it twice.
	//
	// If we are a subsequent manifest, we still need to do the PUT with our tag.
	firstPut := false

	if err := r.work.Do(digest, func() error {
		if err := r.writeDeps(ctx, m); err != nil {
			return err
		}

		firstPut = true
		return r.commitManifest(ctx, ref, m)
	}); err != nil {
		return err
	}

	if firstPut {
		return nil
	}

	return r.commitManifest(ctx, ref, m)
}

func (r *repoWriter) writeChildren(ctx context.Context, idx v1.ImageIndex) error {
	im, err := idx.IndexManifest()
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	for _, desc := range im.Manifests {
		desc := desc
		ref := r.repo.Digest(desc.Digest.String())

		switch desc.MediaType {
		case types.OCIImageIndex, types.DockerManifestList:
			// For recursive index, we want to do a depth-first launching of goroutines
			// to avoid deadlocking.
			//
			// Note that this is rare, so the impact of this should be really small.
			idx, err := idx.ImageIndex(desc.Digest)
			if err != nil {
				return err
			}
			if err := r.writeManifest(ctx, ref, idx); err != nil {
				return err
			}
		case types.OCIManifestSchema1, types.DockerManifestSchema2:
			wg.Add(1)
			r.manifests.Go(func() error {
				defer wg.Done()

				img, err := idx.Image(desc.Digest)
				if err != nil {
					return err
				}

				return r.writeManifest(ctx, ref, img)
			})
		default:
			if !(desc.MediaType.IsDistributable() || r.o.allowNondistributableArtifacts) {
				continue
			}

			// Workaround for #819.
			wl, ok := idx.(withLayer)
			if !ok {
				return fmt.Errorf("unknown media type: %v", desc.MediaType)
			}

			wg.Add(1)
			r.blobs.Go(func() error {
				defer wg.Done()

				l, err := wl.Layer(desc.Digest)
				if err != nil {
					return err
				}
				return r.writeLayer(ctx, l)
			})
		}
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		done <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

func (r *repoWriter) writeChild(ctx context.Context, child partial.Describable, wg sync.WaitGroup) error {
	if idx, ok := child.(v1.ImageIndex); ok {
		// For recursive index, we want to do a depth-first launching of goroutines
		// to avoid deadlocking.
		//
		// Note that this is rare, so the impact of this should be really small.
		return r.writeManifest(ctx, nil, idx)
	}

	if img, ok := child.(v1.Image); ok {
		wg.Add(1)

		r.manifests.Go(func() error {
			defer wg.Done()

			return r.writeManifest(ctx, nil, img)
		})
	}

	// Skip any non-distributable things.
	mt, err := child.MediaType()
	if err != nil {
		return err
	}
	if !(mt.IsDistributable() || r.o.allowNondistributableArtifacts) {
		return nil
	}

	if l, ok := child.(v1.Layer); ok {
		wg.Add(1)
		r.blobs.Go(func() error {
			defer wg.Done()

			return r.writeLayer(ctx, l)
		})
		return nil
	}

	desc, err := partial.Descriptor(child)
	if err != nil {
		return fmt.Errorf("cannot compute descriptor for %T: %w", child, err)
	}
	logs.Warn.Printf("Encountered unknown type: %T = %v", child, desc)
	return nil
}

func (r *repoWriter) lazyWriteChildren(ctx context.Context, idx v1.ImageIndex) error {
	children, err := partial.Manifests(idx)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	for _, child := range children {
		child := child
		if err := r.writeChild(ctx, child, wg); err != nil {
			return err
		}
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		done <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

func (r *repoWriter) manifestExists(ctx context.Context, ref name.Reference, t Taggable) (bool, error) {
	f := &fetcher{
		Ref:     ref,
		Client:  r.w.client,
		context: ctx,
	}

	m, err := taggableToManifest(t)
	if err != nil {
		// Possibly due to streaming layers.
		return false, nil
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

func manifestSize(t Taggable) (int64, error) {
	if ws, ok := t.(interface {
		Size() (int64, error)
	}); ok {
		return ws.Size()
	}

	b, err := t.RawManifest()
	if err != nil {
		return 0, err
	}
	return int64(len(b)), nil
}

func (r *repoWriter) commitManifest(ctx context.Context, ref name.Reference, t Taggable) error {
	if r.o.progress != nil {
		size, err := manifestSize(t)
		if err != nil {
			return err
		}
		r.o.progress.total(size)
	}

	return r.w.commitManifest(ctx, t, ref)
}

func (r *repoWriter) writeLayers(ctx context.Context, img v1.Image) error {
	ls, err := img.Layers()
	if err != nil {
		return err
	}

	cl, err := partial.ConfigLayer(img)
	if err != nil {
		return err
	}

	ls = append(ls, cl)

	var wg sync.WaitGroup
	for _, l := range ls {
		l := l

		// Ignore foreign layers.
		mt, err := l.MediaType()
		if err != nil {
			return err
		}

		if !(mt.IsDistributable() || r.o.allowNondistributableArtifacts) {
			continue
		}

		wg.Add(1)
		r.blobs.Go(func() error {
			defer wg.Done()

			return r.writeLayer(ctx, l)
		})
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		done <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

func (r *repoWriter) writeLayer(ctx context.Context, l v1.Layer) error {
	if ml, ok := l.(*MountableLayer); ok {
		if err := r.maybeUpdateScopes(ml); err != nil {
			return err
		}
	}

	digest, err := l.Digest()
	if err != nil {
		return err
	}

	return r.work.Do(digest, func() error {
		if r.o.progress != nil {
			size, err := l.Size()
			if err != nil {
				return err
			}
			r.o.progress.total(size)
		}
		return r.w.uploadOne(ctx, l)
	})
}
