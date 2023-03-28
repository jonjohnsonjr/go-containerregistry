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

type multiWriter struct {
	sync.Mutex

	manifests []map[name.Reference]Taggable
	blobs     map[v1.Hash]v1.Layer
	images    map[name.Reference]Taggable
	indexes   map[name.Reference]Taggable
}

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

	g, gctx := errgroup.WithContext(o.context)
	g.SetLimit(o.jobs)

	// I'm just using this to lock around the map.
	mw := &multiWriter{
		manifests: []map[name.Reference]Taggable{},
		blobs:     map[v1.Hash]v1.Layer{},
		images:    map[name.Reference]Taggable{},
		indexes:   map[name.Reference]Taggable{},
	}

	for ref, i := range m {
		ref, i := ref, i

		g.Go(func() error {
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

			if img, ok := i.(v1.Image); ok {
				mw.Lock()
				mw.images[ref] = i
				mw.Unlock()
				return mw.addImageBlobs(img, o.allowNondistributableArtifacts)
			}
			if idx, ok := i.(v1.ImageIndex); ok {
				mw.Lock()
				mw.indexes[ref] = i
				mw.Unlock()
				return mw.addIndexBlobs(idx, repo, 0, o.allowNondistributableArtifacts)
			}
			return fmt.Errorf("pushable resource was not Image or ImageIndex: %T", i)
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	// Determine if any of the layers are Mountable, because if so we need
	// to request Pull scope too.
	ls := []v1.Layer{}
	for _, l := range mw.blobs {
		ls = append(ls, l)
	}
	scopes := scopesForUploadingImage(repo, ls)
	tr, err := transport.NewWithContext(o.context, repo.Registry, o.auth, o.transport, scopes)
	if err != nil {
		return err
	}
	w := writer{
		repo:      repo,
		client:    &http.Client{Transport: tr},
		backoff:   o.retryBackoff,
		predicate: o.retryPredicate,
	}

	// Collect the total size of blobs and manifests we're about to write.
	if o.updates != nil {
		w.progress = &progress{updates: o.updates}
		w.progress.lastUpdate = &v1.Update{}
		defer close(o.updates)
		defer func() { _ = w.progress.err(rerr) }()
		for _, b := range mw.blobs {
			size, err := b.Size()
			if err != nil {
				return err
			}
			w.progress.total(size)
		}
		countManifest := func(t Taggable) error {
			b, err := t.RawManifest()
			if err != nil {
				return err
			}
			w.progress.total(int64(len(b)))
			return nil
		}
		for _, i := range mw.images {
			if err := countManifest(i); err != nil {
				return err
			}
		}
		for _, nm := range mw.manifests {
			for _, i := range nm {
				if err := countManifest(i); err != nil {
					return err
				}
			}
		}
		for _, i := range mw.indexes {
			if err := countManifest(i); err != nil {
				return err
			}
		}
	}

	logs.Progress.Printf("Uploading %d blobs", len(mw.blobs))

	// Upload individual blobs and collect any errors.
	blobChan := make(chan v1.Layer, 2*o.jobs)
	ctx := o.context
	g, gctx = errgroup.WithContext(o.context)
	for i := 0; i < o.jobs; i++ {
		// Start N workers consuming blobs to upload.
		g.Go(func() error {
			for b := range blobChan {
				if err := w.uploadOne(gctx, b); err != nil {
					return err
				}
			}
			return nil
		})
	}
	g.Go(func() error {
		defer close(blobChan)
		for _, b := range mw.blobs {
			select {
			case blobChan <- b:
			case <-gctx.Done():
				return gctx.Err()
			}
		}
		return nil
	})
	if err := g.Wait(); err != nil {
		return err
	}

	commitMany := func(ctx context.Context, m map[name.Reference]Taggable) error {
		logs.Progress.Printf("Pushing %d manifests", len(m))
		g, ctx := errgroup.WithContext(ctx)
		// With all of the constituent elements uploaded, upload the manifests
		// to commit the images and indexes, and collect any errors.
		type task struct {
			i   Taggable
			ref name.Reference
		}
		taskChan := make(chan task, 2*o.jobs)
		for i := 0; i < o.jobs; i++ {
			// Start N workers consuming tasks to upload manifests.
			g.Go(func() error {
				for t := range taskChan {
					if err := w.commitManifest(ctx, t.i, t.ref); err != nil {
						return err
					}
				}
				return nil
			})
		}
		go func() {
			for ref, i := range m {
				taskChan <- task{i, ref}
			}
			close(taskChan)
		}()
		return g.Wait()
	}
	// Push originally requested image manifests. These have no
	// dependencies.
	if err := commitMany(ctx, mw.images); err != nil {
		return err
	}
	// Push new manifests from lowest levels up.
	for i := len(mw.manifests) - 1; i >= 0; i-- {
		if err := commitMany(ctx, mw.manifests[i]); err != nil {
			return err
		}
	}
	// Push originally requested index manifests, which might depend on
	// newly discovered manifests.

	return commitMany(ctx, mw.indexes)
}

// addIndexBlobs adds blobs to the set of blobs we intend to upload, and
// returns the latest copy of the ordered collection of manifests to upload.
func (mw *multiWriter) addIndexBlobs(idx v1.ImageIndex, repo name.Repository, lvl int, allowNondistributableArtifacts bool) error {
	mw.Lock()
	if lvl > len(mw.manifests)-1 {
		mw.manifests = append(mw.manifests, map[name.Reference]Taggable{})
	}
	mw.Unlock()

	im, err := idx.IndexManifest()
	if err != nil {
		return err
	}
	for _, desc := range im.Manifests {
		switch desc.MediaType {
		case types.OCIImageIndex, types.DockerManifestList:
			idx, err := idx.ImageIndex(desc.Digest)
			if err != nil {
				return err
			}
			if err := mw.addIndexBlobs(idx, repo, lvl+1, allowNondistributableArtifacts); err != nil {
				return err
			}

			// Also track the sub-index manifest to upload later by digest.
			mw.Lock()
			mw.manifests[lvl][repo.Digest(desc.Digest.String())] = idx
			mw.Unlock()
		case types.OCIManifestSchema1, types.DockerManifestSchema2:
			img, err := idx.Image(desc.Digest)
			if err != nil {
				return err
			}
			if err := mw.addImageBlobs(img, allowNondistributableArtifacts); err != nil {
				return err
			}

			// Also track the sub-image manifest to upload later by digest.
			mw.Lock()
			mw.manifests[lvl][repo.Digest(desc.Digest.String())] = img
			mw.Unlock()
		default:
			// Workaround for #819.
			if wl, ok := idx.(withLayer); ok {
				layer, err := wl.Layer(desc.Digest)
				if err != nil {
					return err
				}
				if err := mw.addLayerBlob(layer, allowNondistributableArtifacts); err != nil {
					return err
				}
			} else {
				return fmt.Errorf("unknown media type: %v", desc.MediaType)
			}
		}
	}
	return nil
}

func (mw *multiWriter) addLayerBlob(l v1.Layer, allowNondistributableArtifacts bool) error {
	// Ignore foreign layers.
	mt, err := l.MediaType()
	if err != nil {
		return err
	}

	if mt.IsDistributable() || allowNondistributableArtifacts {
		d, err := l.Digest()
		if err != nil {
			return err
		}

		mw.Lock()
		mw.blobs[d] = l
		mw.Unlock()
	}

	return nil
}

func (mw *multiWriter) addImageBlobs(img v1.Image, allowNondistributableArtifacts bool) error {
	ls, err := img.Layers()
	if err != nil {
		return err
	}
	// Collect all layers.
	for _, l := range ls {
		if err := mw.addLayerBlob(l, allowNondistributableArtifacts); err != nil {
			return err
		}
	}

	// Collect config blob.
	cl, err := partial.ConfigLayer(img)
	if err != nil {
		return err
	}
	return mw.addLayerBlob(cl, allowNondistributableArtifacts)
}
