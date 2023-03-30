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
	"github.com/google/go-containerregistry/pkg/v1/types"
	"golang.org/x/sync/errgroup"
)

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

type multiWriter struct {
	w    *writer
	repo name.Repository
	o    *options

	work *workers

	scopeLock sync.Mutex
	scopeSet  map[string]struct{}
	scopes    []string

	roots     *errgroup.Group
	manifests *errgroup.Group
	blobs     *errgroup.Group
}

func (mw *multiWriter) Wait() error {
	if err := mw.roots.Wait(); err != nil {
		return err
	}

	if err := mw.manifests.Wait(); err != nil {
		return err
	}

	if err := mw.blobs.Wait(); err != nil {
		return err
	}

	return nil
}

func (mw *multiWriter) maybeUpdateScopes(ml *MountableLayer) error {
	if ml.Reference.Context().String() == mw.repo.String() {
		return nil
	}
	if ml.Reference.Context().Registry.String() != mw.repo.Registry.String() {
		return nil
	}

	scope := ml.Reference.Scope(transport.PullScope)

	mw.scopeLock.Lock()
	defer mw.scopeLock.Unlock()

	if _, ok := mw.scopeSet[scope]; !ok {
		mw.scopeSet[scope] = struct{}{}
		mw.scopes = append(mw.scopes, scope)

		logs.Debug.Printf("Refreshing token to add scope %q", scope)
		wt, err := transport.NewWithContext(mw.o.context, mw.repo.Registry, mw.o.auth, mw.o.transport, mw.scopes)
		if err != nil {
			return err
		}
		mw.w.client = &http.Client{Transport: wt}
	}

	return nil
}

var manifestTypes = append(acceptableImageMediaTypes, acceptableIndexMediaTypes...)

// MultiWrite writes the given Images or ImageIndexes to the given refs, as
// efficiently as possible, by deduping shared layer blobs and uploading layers
// in parallel, then uploading all manifests in parallel.
//
// Current limitations:
// - All refs must share the same repository.
// - Images cannot consist of stream.Layers.
func MultiWrite(todo map[name.Reference]Taggable, options ...Option) (rerr error) {
	// Determine the repository being pushed to; if asked to push to
	// multiple repositories, give up.
	var repo, zero name.Repository
	for ref := range todo {
		if repo == zero {
			repo = ref.Context()
		} else if ref.Context() != repo {
			return fmt.Errorf("MultiWrite can only push to the same repository (saw %q and %q)", repo, ref.Context())
		}
	}

	o, err := makeOptions(repo, options...)
	if err != nil {
		return err
	}
	ctx := o.context
	scope := repo.Scope(transport.PushScope)
	scopes := []string{scope}
	rt, err := transport.NewWithContext(ctx, repo.Registry, o.auth, o.transport, scopes)
	if err != nil {
		return err
	}

	w := &writer{
		repo:      repo,
		client:    &http.Client{Transport: rt},
		backoff:   o.retryBackoff,
		predicate: o.retryPredicate,
	}

	// I'm just using this to lock around the map.
	mw := &multiWriter{
		w:    w,
		repo: repo,
		o:    o,
		work: &workers{},
		scopeSet: map[string]struct{}{
			scope: struct{}{},
		},
		scopes: scopes,
	}

	// Collect the total size of blobs and manifests we're about to write.
	if o.updates != nil {
		w.progress = &progress{updates: o.updates}
		w.progress.lastUpdate = &v1.Update{}
		defer close(o.updates)
		defer func() { _ = w.progress.err(rerr) }()
	}

	mw.blobs, _ = errgroup.WithContext(ctx)
	mw.blobs.SetLimit(o.jobs)

	mw.manifests, _ = errgroup.WithContext(ctx)
	mw.manifests.SetLimit(o.jobs)

	// Separate from manifests so we don't block our children.
	mw.roots, ctx = errgroup.WithContext(ctx)
	mw.roots.SetLimit(o.jobs)

	for ref, i := range todo {
		ref, i := ref, i

		mw.roots.Go(func() error {
			// Make it so you can just pass the results of remote.Get into this.
			if desc, ok := i.(*Descriptor); ok {
				if desc.MediaType.IsIndex() {
					idx, err := desc.ImageIndex()
					if err != nil {
						return err
					}
					i = idx
				} else {
					img, err := desc.Image()
					if err != nil {
						return err
					}
					i = img

				}
			}

			m, ok := i.(manifest)
			if !ok {
				return mw.commitManifest(ctx, ref, i)
			}

			if exists, err := mw.manifestExists(ctx, ref, m); err != nil {
				return err
			} else if exists {
				return nil
			}

			return mw.writeManifest(ctx, ref, m)
		})
	}

	return mw.Wait()
}

func (mw *multiWriter) writeDeps(ctx context.Context, m manifest) error {
	if img, ok := m.(v1.Image); ok {
		return mw.writeLayers(ctx, img)
	}

	if idx, ok := m.(v1.ImageIndex); ok {
		return mw.writeChildren(ctx, idx)
	}

	return fmt.Errorf("pushable resource was not Image or ImageIndex: %T", m)
}

func (mw *multiWriter) writeManifest(ctx context.Context, ref name.Reference, m manifest) error {
	digest, err := m.Digest()
	if err != nil {
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

	if err := mw.work.Do(digest, func() error {
		if err := mw.writeDeps(ctx, m); err != nil {
			return err
		}

		firstPut = true
		return mw.commitManifest(ctx, ref, m)
	}); err != nil {
		return err
	}

	if firstPut {
		return nil
	}

	return mw.commitManifest(ctx, ref, m)
}

func (mw *multiWriter) writeChildren(ctx context.Context, idx v1.ImageIndex) error {
	im, err := idx.IndexManifest()
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	for _, desc := range im.Manifests {
		desc := desc
		ref := mw.repo.Digest(desc.Digest.String())

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
			if err := mw.writeManifest(ctx, ref, idx); err != nil {
				return err
			}
		case types.OCIManifestSchema1, types.DockerManifestSchema2:
			wg.Add(1)
			mw.manifests.Go(func() error {
				defer wg.Done()

				img, err := idx.Image(desc.Digest)
				if err != nil {
					return err
				}

				return mw.writeManifest(ctx, ref, img)
			})
		default:
			if !(desc.MediaType.IsDistributable() || mw.o.allowNondistributableArtifacts) {
				continue
			}

			// Workaround for #819.
			wl, ok := idx.(withLayer)
			if !ok {
				return fmt.Errorf("unknown media type: %v", desc.MediaType)
			}

			wg.Add(1)
			mw.blobs.Go(func() error {
				defer wg.Done()

				l, err := wl.Layer(desc.Digest)
				if err != nil {
					return err
				}
				return mw.writeLayer(ctx, l)
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

func (mw *multiWriter) manifestExists(ctx context.Context, ref name.Reference, pd partial.Describable) (bool, error) {
	f := &fetcher{
		Ref:     ref,
		Client:  mw.w.client,
		context: ctx,
	}
	digest, err := pd.Digest()
	if err != nil {
		// Possibly due to streaming layers.
		return false, nil
	}
	got, err := f.headManifest(ref, manifestTypes)
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

func manifestSize(i Taggable) (int64, error) {
	if ws, ok := i.(interface {
		Size() (int64, error)
	}); ok {
		return ws.Size()
	}

	b, err := i.RawManifest()
	if err != nil {
		return 0, err
	}
	return int64(len(b)), nil
}

func (mw *multiWriter) commitManifest(ctx context.Context, ref name.Reference, i Taggable) error {
	if mw.o.updates != nil {
		size, err := manifestSize(i)
		if err != nil {
			return err
		}
		mw.w.progress.total(size)
	}

	return mw.w.commitManifest(ctx, i, ref)
}

func (mw *multiWriter) writeLayers(ctx context.Context, img v1.Image) error {
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

		if !(mt.IsDistributable() || mw.o.allowNondistributableArtifacts) {
			continue
		}

		wg.Add(1)
		mw.blobs.Go(func() error {
			defer wg.Done()

			return mw.writeLayer(ctx, l)
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

func (mw *multiWriter) writeLayer(ctx context.Context, l v1.Layer) error {
	if ml, ok := l.(*MountableLayer); ok {
		if err := mw.maybeUpdateScopes(ml); err != nil {
			return err
		}
	}

	digest, err := l.Digest()
	if err != nil {
		return err
	}

	return mw.work.Do(digest, func() error {
		if mw.o.updates != nil {
			size, err := l.Size()
			if err != nil {
				return err
			}
			mw.w.progress.total(size)
		}
		return mw.w.uploadOne(ctx, l)
	})
}
