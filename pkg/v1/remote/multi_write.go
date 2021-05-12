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
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"golang.org/x/sync/errgroup"
)

type task interface {
	// used to dedupe in-flight work
	key() string

	// the actual work to perform
	run() error

	// dependencies of this task
	tasks() []task

	// for progress
	size() int64

	// Stolen from context.Context so we can wait
	Done() <-chan struct{}
	Err() error
}

func newManifestTask(mw *multiwriter, ref name.Reference, taggable Taggable) (*manifestTask, error) {
	t := &manifestTask{
		w:        mw.w,
		taggable: taggable,
		ref:      ref,
		done:     make(chan struct{}),
	}
	switch m := taggable.(type) {
	case v1.Image:
		layers, err := m.Layers()
		if err != nil {
			return nil, err
		}
		cl, err := partial.ConfigLayer(m)
		if err != nil {
			return nil, err
		}
		layers = append(layers, cl)

		// Determine if we need to re-auth with the ability to mount.
		if err := mw.maybeReauth(ref.Context(), layers); err != nil {
			return nil, err
		}

		t.subtasks = make([]task, 0, len(layers)+1)
		for _, layer := range layers {
			subtask, err := newBlobTask(mw, layer)
			if err != nil {
				return nil, err
			}
			// subtask can be nil for non-distributable layers
			if subtask != nil {
				t.subtasks = append(t.subtasks, subtask)
			}
		}
	case v1.ImageIndex:
		im, err := m.IndexManifest()
		if err != nil {
			return nil, err
		}
		t.subtasks = make([]task, 0, len(im.Manifests)+1)
		for _, desc := range im.Manifests {
			switch desc.MediaType {
			case types.OCIImageIndex, types.DockerManifestList:
				idx, err := m.ImageIndex(desc.Digest)
				if err != nil {
					return nil, err
				}
				subtask, err := newManifestTask(mw, ref.Context().Digest(desc.Digest.String()), idx)
				if err != nil {
					return nil, err
				}
				t.subtasks = append(t.subtasks, subtask)
			case types.OCIManifestSchema1, types.DockerManifestSchema2:
				img, err := m.Image(desc.Digest)
				if err != nil {
					return nil, err
				}
				subtask, err := newManifestTask(mw, ref.Context().Digest(desc.Digest.String()), img)
				if err != nil {
					return nil, err
				}
				t.subtasks = append(t.subtasks, subtask)
			default:
				// Workaround for #819.
				if wl, ok := m.(withLayer); ok {
					layer, err := wl.Layer(desc.Digest)
					if err != nil {
						return nil, err
					}
					subtask, err := newBlobTask(mw, layer)
					if err != nil {
						return nil, err
					}
					// subtask can be nil for non-distributable layers
					if subtask != nil {
						t.subtasks = append(t.subtasks, subtask)
					}
				} else {
					return nil, fmt.Errorf("unknown media type: %v", desc.MediaType)
				}
			}
		}
	}

	b, err := t.taggable.RawManifest()
	if err != nil {
		return nil, err
	}
	t.digest, t.bytes, err = v1.SHA256(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	return t, nil
}

type manifestTask struct {
	w        *writer
	digest   v1.Hash
	taggable Taggable
	ref      name.Reference
	bytes    int64
	done     chan struct{}
	err      error

	subtasks []task
}

func (t *manifestTask) key() string {
	return t.digest.String()
}

func (t *manifestTask) tasks() []task {
	return t.subtasks
}

func (t *manifestTask) run() error {
	err := t.w.commitManifest(t.taggable, t.ref)
	t.err = err
	close(t.done)
	return err
}

func (t *manifestTask) size() int64 {
	return t.bytes
}

func (t *manifestTask) Done() <-chan struct{} {
	return t.done
}

func (t *manifestTask) Err() error {
	return t.err
}

func newBlobTask(mw *multiwriter, layer v1.Layer) (*blobTask, error) {
	t := blobTask{
		w:     mw.w,
		layer: layer,
		done:  make(chan struct{}),
	}

	mt, err := layer.MediaType()
	if err != nil {
		return nil, err
	}
	if mt.IsDistributable() || mw.w.allowNondistributableArtifacts {
		digest, err := layer.Digest()
		if err != nil {
			return nil, err
		}
		t.digest = digest

		if mw.w.updates != nil {
			size, err := layer.Size()
			if err != nil {
				return nil, err
			}
			t.bytes = size
		}
		return &t, nil
	}

	return nil, nil
}

type blobTask struct {
	w      *writer
	digest v1.Hash
	layer  v1.Layer
	bytes  int64
	done   chan struct{}
	err    error
}

func (t *blobTask) key() string {
	return t.digest.String()
}

func (t *blobTask) tasks() []task {
	// Blobs don't have any dependencies.
	return nil
}

func (t *blobTask) run() error {
	err := t.w.uploadOne(t.layer)
	t.err = err
	close(t.done)
	return err
}

func (t *blobTask) size() int64 {
	return t.bytes
}

func (t *blobTask) Done() <-chan struct{} {
	return t.done
}

func (t *blobTask) Err() error {
	return t.err
}

// multiwriter manages deduplication of tasks and the dependency graph
type multiwriter struct {
	w *writer

	reauth   sync.Mutex
	scopeSet map[string]struct{}
	scopes   []string
	o        *options
	// string -> task
	//
	// the key is either v1.Hash.String() or name.Reference.String()
	//
	// Used for deduplicating in-flight work
	work  sync.Map
	queue chan task
}

// depth-first enqueue
func (mw *multiwriter) enqueue(t task) {
	// dedupe before recursing
	actual, loaded := mw.work.LoadOrStore(t.key(), t)
	if loaded {
		// if we're deduping, and this ref is new, enqueue for the tag PUT
		if mt, ok := t.(*manifestTask); ok {
			if lt, ok := actual.(*manifestTask); ok {
				if mt.ref.String() != lt.ref.String() {
					if mw.w.updates != nil {
						mw.increment(t.size())
					}
					mw.queue <- t
				}
			}
		}

		// No other work to do if we're deduplicating.
		return
	}

	for _, subtask := range t.tasks() {
		mw.enqueue(subtask)
	}

	if mw.w.updates != nil {
		mw.increment(t.size())
	}
	mw.queue <- t
}

// wait for subtasks to finish, then run
func (mw *multiwriter) run(t task) error {
	for _, subtask := range t.tasks() {
		// It's important that we always enqueue dependencies first so that
		// this doesn't deadlock.
		if err := mw.wait(subtask); err != nil {
			return err
		}
	}
	return t.run()
}

func (mw *multiwriter) wait(t task) error {
	if w, ok := mw.work.Load(t.key()); ok {
		if wt, ok := w.(task); ok {
			// Dedupe to the in-flight equivalent.
			t = wt
		} else {
			return fmt.Errorf("task %q is not a task, aborting", t.key())
		}
	}
	select {
	case <-t.Done():
		return t.Err()
	}
	return nil
}

func (mw *multiwriter) increment(n int64) {
	atomic.AddInt64(&mw.w.lastUpdate.Total, n)
}

func (mw *multiwriter) shouldReauth(scopes []string) bool {
	for _, scope := range scopes {
		if _, ok := mw.scopeSet[scope]; !ok {
			return true
		}
	}
	return false
}

// Check to see if the scopes are different for this set of layers, and if so, redo
// the token exchange so that we can mount successfully.
func (mw *multiwriter) maybeReauth(repo name.Repository, layers []v1.Layer) error {
	scopes := scopesForUploadingImage(repo, layers)
	if mw.shouldReauth(scopes) {
		mw.reauth.Lock()
		defer mw.reauth.Unlock()
		if !mw.shouldReauth(scopes) {
			return nil
		}

		for _, scope := range scopes {
			if _, ok := mw.scopeSet[scope]; !ok {
				logs.Debug.Printf("reauthenticating for scope: %q", scope)
				mw.scopes = append(mw.scopes, scope)
				mw.scopeSet[scope] = struct{}{}
			}
		}
		// TODO: We should handle muliple destination repositories.
		tr, err := transport.NewWithContext(mw.o.context, repo.Registry, mw.o.auth, mw.o.transport, mw.scopes)
		if err != nil {
			return err
		}
		mw.w.client = &http.Client{Transport: tr}
	}

	return nil
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

	scopes := scopesForUploadingImage(repo, nil)
	tr, err := transport.NewWithContext(o.context, repo.Registry, o.auth, o.transport, scopes)
	if err != nil {
		return err
	}
	w := &writer{
		repo:                           repo,
		client:                         &http.Client{Transport: tr},
		allowNondistributableArtifacts: o.allowNondistributableArtifacts,
		context:                        o.context,
		updates:                        o.updates,
		lastUpdate:                     &v1.Update{},
	}
	mw := &multiwriter{
		w:        w,
		scopeSet: scopeSet(repo, nil),
		scopes:   scopes,
		o:        o,
		queue:    make(chan task, o.jobs*10),
	}

	// Collect the total size of blobs and manifests we're about to write.
	if o.updates != nil {
		defer close(o.updates)
		defer func() { sendError(o.updates, rerr) }()
	}

	type input struct {
		ref name.Reference
		t   Taggable
	}
	inputChan := make(chan input, 2*o.jobs)

	g, ctx := errgroup.WithContext(o.context)

	// Pull tasks off the queue and run them.
	for i := 0; i < o.jobs; i++ {
		g.Go(func() error {
			for t := range mw.queue {
				if err := mw.run(t); err != nil {
					return err
				}
			}
			return nil
		})
	}

	// Create and enqueue tasks for the runners.
	g.Go(func() error {
		defer close(mw.queue)
		q, ctx := errgroup.WithContext(ctx)
		for i := 0; i < o.jobs; i++ {
			q.Go(func() error {
				for in := range inputChan {
					t, err := newManifestTask(mw, in.ref, in.t)
					if err != nil {
						return err
					}
					select {
					case <-ctx.Done():
						return ctx.Err()
					default:
						mw.enqueue(t)
					}
				}
				return nil
			})
		}
		return q.Wait()
	})

	// Start enqueueing inputs for the task creators.
	g.Go(func() error {
		defer close(inputChan)
		for ref, t := range m {
			select {
			case inputChan <- input{ref, t}:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})

	return g.Wait()
}
