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

type task struct {
	i    manifest
	ref  name.Reference
	deps map[string]struct{}
}

type multiWriter struct {
	sync.Mutex

	manifests []map[name.Reference]manifest
	blobs     map[v1.Hash]v1.Layer
	images    map[name.Reference]manifest
	indexes   map[name.Reference]manifest

	// Stuff that is in flight so we don't do it twice.
	// Key is a manifest ref or blob digest.
	inflight map[string]bool
	wg       sync.WaitGroup

	// Key is always digest
	waiting map[string][]task

	// Upload individual blobs and collect any errors.
	blobChan chan v1.Layer

	// Upload manifests
	manifestChan chan task

	todo []task
}

func (mw *multiWriter) requeueWaiters(waiters []task, finisher string) {
	for _, t := range waiters {
		delete(t.deps, finisher)

		mw.requeueTask(t)
	}
}

func (mw *multiWriter) requeueTask(t task) {
	logs.Progress.Printf("requeue %s", t.ref)
	mw.todo = append(mw.todo, t)
}

var manifestTypes = append(acceptableImageMediaTypes, acceptableIndexMediaTypes...)

// MultiWrite writes the given Images or ImageIndexes to the given refs, as
// efficiently as possible, by deduping shared layer blobs and uploading layers
// in parallel, then uploading all manifests in parallel.
//
// Current limitations:
// - All refs must share the same repository.
// - Images cannot consist of stream.Layers.
func MultiWrite(m map[name.Reference]Taggable, options ...Option) (rerr error) {
	// Determine the repository being pushed to; if asked to push to
	// multiple repositories, give up.
	var repo, zero name.Repository
	for ref := range m {
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
	scope := repo.Scope(transport.PushScope)
	scopes := []string{scope}
	rt, err := transport.NewWithContext(o.context, repo.Registry, o.auth, o.transport, scopes)
	if err != nil {
		return err
	}
	fclient := &http.Client{Transport: rt}

	// I'm just using this to lock around the map.
	mw := &multiWriter{
		manifests:    []map[name.Reference]manifest{},
		blobs:        map[v1.Hash]v1.Layer{},
		images:       map[name.Reference]manifest{},
		indexes:      map[name.Reference]manifest{},
		inflight:     map[string]bool{},
		waiting:      map[string][]task{},
		todo:         []task{},
		blobChan:     make(chan v1.Layer, 10*o.jobs),
		manifestChan: make(chan task, 10*o.jobs),
	}

	var scopeLock sync.Mutex
	scopeSet := map[string]struct{}{
		scope: struct{}{},
	}

	// If we don't have mountable layers, we can reuse the read transport.
	w := &writer{
		repo:      repo,
		client:    &http.Client{Transport: rt},
		backoff:   o.retryBackoff,
		predicate: o.retryPredicate,
	}

	// Collect the total size of blobs and manifests we're about to write.
	if o.updates != nil {
		w.progress = &progress{updates: o.updates}
		w.progress.lastUpdate = &v1.Update{}
		defer close(o.updates)
		defer func() { _ = w.progress.err(rerr) }()
	}

	maybeUpdateScopes := func(ml *MountableLayer) error {
		if ml.Reference.Context().String() == repo.String() {
			return nil
		}
		if ml.Reference.Context().Registry.String() != repo.Registry.String() {
			return nil
		}

		scope := ml.Reference.Scope(transport.PullScope)

		scopeLock.Lock()
		defer scopeLock.Unlock()

		if _, ok := scopeSet[scope]; !ok {
			scopeSet[scope] = struct{}{}
			scopes = append(scopes, scope)

			logs.Debug.Printf("Refreshing token to add scope %q", scope)
			mw.Lock()
			wt, err := transport.NewWithContext(o.context, repo.Registry, o.auth, o.transport, scopes)
			if err != nil {
				return err
			}
			w.client = &http.Client{Transport: wt}
			mw.Unlock()
			// We need to update our scopes.
		}

		return nil
	}

	meta, ctx := errgroup.WithContext(o.context)
	meta.Go(func() error {
		for ref, i := range m {
			ref, i := ref, i

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

			// This should always be true.
			if pd, ok := i.(partial.Describable); ok {
				f := &fetcher{
					Ref:     ref,
					Client:  fclient,
					context: ctx,
				}
				want, err := partial.Descriptor(pd)
				if err != nil {
					return err
				}
				got, err := f.headManifest(ref, manifestTypes)
				if err == nil {
					if want.Digest == got.Digest {
						if tag, ok := ref.(name.Tag); ok {
							logs.Progress.Printf("existing manifest: %s@%s", tag.Identifier(), got.Digest)
						} else {
							logs.Progress.Print("existing manifest: ", got.Digest)
						}
						return nil
					}
				}
			} else {
				logs.Warn.Printf("taggable was %T", i)
			}

			if img, ok := i.(v1.Image); ok {
				deps, err := mw.addImageBlobs(ctx, img, ref, o.allowNondistributableArtifacts)
				if err != nil {
					return err
				}
				t := task{img, ref, deps}

				if len(deps) == 0 {
					mw.Lock()
					mw.inflight[ref.String()] = false
					mw.Unlock()

					select {
					case mw.manifestChan <- t:
						mw.wg.Add(1)
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				return nil
			}

			if idx, ok := i.(v1.ImageIndex); ok {
				deps, err := mw.addIndexBlobs(ctx, idx, ref, repo, 0, o.allowNondistributableArtifacts)
				if err != nil {
					return err
				}
				t := task{idx, ref, deps}

				if len(deps) == 0 {
					mw.Lock()
					mw.inflight[ref.String()] = false
					mw.Unlock()

					select {
					case mw.manifestChan <- t:
						mw.wg.Add(1)
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				return nil
			}

			return fmt.Errorf("pushable resource was not Image or ImageIndex: %T", i)
		}

		close(mw.blobChan)
		defer close(mw.manifestChan)

		for {
			logs.Progress.Printf("Waiting")
			mw.wg.Wait()
			logs.Progress.Printf("Finished waiting")

			mw.Lock()
			if len(mw.todo) == 0 {
				return nil
			}

			todos := mw.todo[:]
			mw.todo = []task{}
			mw.Unlock()

			logs.Progress.Printf("Found %d to requeue", len(todos))
			for _, t := range todos {
				select {
				case mw.manifestChan <- t:
					mw.wg.Add(1)
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}

		return nil
	})

	meta.Go(func() error {
		logs.Progress.Print("Starting blob uploads")
		g, ctx := errgroup.WithContext(ctx)
		g.SetLimit(o.jobs)
		for b := range mw.blobChan {
			b := b
			if ml, ok := b.(*MountableLayer); ok {
				if err := maybeUpdateScopes(ml); err != nil {
					return err
				}
			}
			if o.updates != nil {
				size, err := b.Size()
				if err != nil {
					return err
				}
				w.progress.total(size)
			}

			g.Go(func() error {
				if err := w.uploadOne(ctx, b); err != nil {
					return err
				}
				digest, err := b.Digest()
				if err != nil {
					return err
				}
				key := digest.String()

				mw.Lock()
				defer mw.Unlock()

				mw.inflight[key] = true
				todo, ok := mw.waiting[key]
				if ok {
					delete(mw.waiting, key)
					mw.requeueWaiters(todo, key)
				}

				return nil
			})
		}
		return g.Wait()
	})

	meta.Go(func() error {
		logs.Progress.Print("Starting manifest uploads")
		g, ctx := errgroup.WithContext(ctx)
		g.SetLimit(o.jobs)
		for t := range mw.manifestChan {
			t := t

			g.Go(func() error {
				defer mw.wg.Done()
				mw.Lock()
				if mw.inflight[t.ref.String()] {
					logs.Progress.Printf("already uploaded %s", t.ref)
					mw.Unlock()
					return nil
				}
				for dep := range t.deps {
					done, ok := mw.inflight[dep]
					if !ok {
						mw.Unlock()
						return fmt.Errorf("missing dep %q for %q, deps=%v", dep, t.ref, t.deps)
					}
					if done {
						delete(t.deps, dep)
					}
				}
				if len(t.deps) != 0 {
					mw.requeueTask(t)
					mw.Unlock()
					return nil
				}
				mw.Unlock()

				if o.updates != nil {
					if ws, ok := t.i.(interface {
						Size() (int64, error)
					}); ok {
						size, err := ws.Size()
						if err != nil {
							return err
						}
						w.progress.total(size)
					} else {
						b, err := t.i.RawManifest()
						if err != nil {
							return err
						}
						w.progress.total(int64(len(b)))
					}
				}

				if err := w.commitManifest(ctx, t.i, t.ref); err != nil {
					return err
				}

				digest, err := t.i.Digest()
				if err != nil {
					return err
				}
				key := digest.String()

				mw.Lock()
				mw.inflight[t.ref.String()] = true
				todo, ok := mw.waiting[key]
				if ok {
					mw.requeueWaiters(todo, key)
				}
				mw.Unlock()

				return nil
			})
		}
		return g.Wait()
	})

	return meta.Wait()
}

// addIndexBlobs adds blobs to the set of blobs we intend to upload, and
// returns the latest copy of the ordered collection of manifests to upload.
func (mw *multiWriter) addIndexBlobs(ctx context.Context, idx v1.ImageIndex, ref name.Reference, repo name.Repository, lvl int, allowNondistributableArtifacts bool) (map[string]struct{}, error) {
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}

	deps := make(map[string]struct{}, len(im.Manifests))
	for _, desc := range im.Manifests {
		deps[desc.Digest.String()] = struct{}{}
	}

	for _, desc := range im.Manifests {
		childRef := repo.Digest(desc.Digest.String())
		key := childRef.String()
		waitKey := desc.Digest.String()

		switch desc.MediaType {
		case types.OCIImageIndex, types.DockerManifestList:
			childIdx, err := idx.ImageIndex(desc.Digest)
			if err != nil {
				return nil, err
			}
			childDeps, err := mw.addIndexBlobs(ctx, childIdx, childRef, repo, lvl+1, allowNondistributableArtifacts)
			if err != nil {
				return nil, err
			}

			if len(childDeps) == 0 {
				mw.Lock()
				mw.inflight[key] = false
				mw.Unlock()

				t := task{childIdx, childRef, childDeps}
				select {
				case mw.manifestChan <- t:
					mw.wg.Add(1)
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}

			mw.Lock()
			if done, ok := mw.inflight[key]; ok {
				if done {
					delete(deps, key)
					mw.Unlock()
					continue
				}

				waiting, ok := mw.waiting[waitKey]
				if !ok {
					waiting = []task{}
				}
				waiting = append(waiting, task{idx, ref, deps})
				mw.waiting[waitKey] = waiting
			}
			mw.Unlock()
		case types.OCIManifestSchema1, types.DockerManifestSchema2:
			img, err := idx.Image(desc.Digest)
			if err != nil {
				return nil, err
			}
			childDeps, err := mw.addImageBlobs(ctx, img, childRef, allowNondistributableArtifacts)
			if err != nil {
				return nil, err
			}

			if len(childDeps) == 0 {
				mw.Lock()
				mw.inflight[key] = false
				mw.Unlock()

				t := task{img, childRef, childDeps}
				select {
				case mw.manifestChan <- t:
					mw.wg.Add(1)
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}

			mw.Lock()
			if done, ok := mw.inflight[key]; ok {
				if done {
					delete(deps, key)
					mw.Unlock()
					continue
				}

				waiting, ok := mw.waiting[waitKey]
				if !ok {
					waiting = []task{}
				}
				waiting = append(waiting, task{idx, ref, deps})
				mw.waiting[waitKey] = waiting
			}
			mw.Unlock()
		default:
			// Workaround for #819.
			if wl, ok := idx.(withLayer); ok {
				layer, err := wl.Layer(desc.Digest)
				if err != nil {
					return nil, err
				}
				done, err := mw.addLayerBlob(ctx, idx, ref, layer, allowNondistributableArtifacts)
				if err != nil {
					return nil, err
				}
				if done {
					delete(deps, key)
				}
			} else {
				return nil, fmt.Errorf("unknown media type: %v", desc.MediaType)
			}
		}
	}
	return deps, nil
}

func (mw *multiWriter) addLayerBlob(ctx context.Context, parent manifest, ref name.Reference, l v1.Layer, allowNondistributableArtifacts bool) (bool, error) {
	// Ignore foreign layers.
	mt, err := l.MediaType()
	if err != nil {
		return false, err
	}

	if !(mt.IsDistributable() || allowNondistributableArtifacts) {
		return true, nil
	}

	digest, err := l.Digest()
	if err != nil {
		return false, err
	}

	key := digest.String()
	mw.Lock()
	if done, ok := mw.inflight[key]; ok {
		if done {
			mw.Unlock()
			return true, nil
		}

		waiting, ok := mw.waiting[key]
		if !ok {
			waiting = []task{}
		}
		waiting = append(waiting, task{parent, ref, nil})
		mw.waiting[key] = waiting
		mw.Unlock()
	} else {
		mw.inflight[key] = false
		mw.Unlock()

		select {
		case mw.blobChan <- l:
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}

	return false, nil
}

func (mw *multiWriter) addImageBlobs(ctx context.Context, img v1.Image, ref name.Reference, allowNondistributableArtifacts bool) (map[string]struct{}, error) {
	ls, err := img.Layers()
	if err != nil {
		return nil, err
	}

	cl, err := partial.ConfigLayer(img)
	if err != nil {
		return nil, err
	}

	ls = append(ls, cl)

	deps := make(map[string]struct{}, len(ls)+1)

	// Collect all layers.
	for _, l := range ls {
		dig, err := l.Digest()
		if err != nil {
			return nil, err
		}

		done, err := mw.addLayerBlob(ctx, img, ref, l, allowNondistributableArtifacts)
		if err != nil {
			return nil, err
		}

		if !done {
			deps[dig.String()] = struct{}{}
		}
	}

	return deps, nil
}
