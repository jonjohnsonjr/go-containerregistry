// Copyright 2018 Google LLC All Rights Reserved.
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

package gcrane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-containerregistry/internal/retry"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"golang.org/x/sync/errgroup"
)

// Keychain tries to use google-specific credential sources, falling back to
// the DefaultKeychain (config-file based).
var Keychain = authn.NewMultiKeychain(google.Keychain, authn.DefaultKeychain)

// GCRBackoff returns a retry.Backoff that is suitable for use with gcr.io.
//
// These numbers are based on GCR's posted quotas:
// https://cloud.google.com/container-registry/quotas
// -  30k requests per 10 minutes.
// - 500k requests per 24 hours.
//
// On error, we will wait for:
// - 6 seconds (in case of very short term 429s from GCS), then
// - 1 minute (in case of temporary network issues), then
// - 10 minutes (to get around GCR 10 minute quotas), then fail.
//
// TODO: In theory, we could keep retrying until the next day to get around the 500k limit.
func GCRBackoff() retry.Backoff {
	return retry.Backoff{
		Duration: 6 * time.Second,
		Factor:   10.0,
		Jitter:   0.1,
		Steps:    3,
		Cap:      1 * time.Hour,
	}
}

// Copy copies a remote image or index from src to dst.
func Copy(src, dst string, opts ...Option) error {
	o := makeOptions(opts...)
	// Just reuse crane's copy logic with gcrane's credential logic.
	return crane.Copy(src, dst, o.crane...)
}

// CopyRepository copies everything from the src GCR repository to the
// dst GCR repository.
func CopyRepository(ctx context.Context, src, dst string, opts ...Option) error {
	o := makeOptions(opts...)
	return recursiveCopy(ctx, src, dst, o)
}

type copier struct {
	srcRepo name.Repository
	dstRepo name.Repository

	opt *options

	puller *remote.Puller
	pusher *remote.Pusher
}

func newCopier(src, dst string, o *options) (*copier, error) {
	srcRepo, err := name.NewRepository(src)
	if err != nil {
		return nil, fmt.Errorf("parsing repo %q: %w", src, err)
	}

	dstRepo, err := name.NewRepository(dst)
	if err != nil {
		return nil, fmt.Errorf("parsing repo %q: %w", dst, err)
	}

	puller, err := remote.NewPuller(o.remote...)
	if err != nil {
		return nil, err
	}

	pusher, err := remote.NewPusher(o.remote...)
	if err != nil {
		return nil, err
	}

	return &copier{
		srcRepo: srcRepo,
		dstRepo: dstRepo,
		opt:     o,
		puller:  puller,
		pusher:  pusher,
	}, nil
}

// recursiveCopy copies images from repo src to repo dst.
func recursiveCopy(ctx context.Context, src, dst string, o *options) error {
	c, err := newCopier(src, dst, o)
	if err != nil {
		return err
	}

	return c.copyRepo(ctx, c.srcRepo)
}

// copyRepo figures out the name for our destination repo (newRepo), lists the
// contents of newRepo, calculates the diff of what needs to be copied, then
// fires off a goroutine to copy the diff and another to copy children.
func (c *copier) copyRepo(ctx context.Context, oldRepo name.Repository) error {
	want, err := c.list(ctx, oldRepo)
	if err != nil {
		return err
	}

	if len(want.Children) == 0 {
		return c.copyImages(ctx, oldRepo, want)
	}

	g, ctx := errgroup.WithContext(ctx)
	g.Go(backoff(GCRBackoff(), func() error {
		return c.copyImages(ctx, oldRepo, want)
	}))

	for _, path := range want.Children {
		child, err := name.NewRepository(fmt.Sprintf("%s/%s", oldRepo, path), name.StrictValidation)
		if err != nil {
			return fmt.Errorf("unexpected path failure: %w", err)
		}

		g.Go(func() error {
			return c.copyRepo(ctx, child)
		})
	}

	return g.Wait()
}

// pulled out into a method to hide the backoff grossness
func (c *copier) list(ctx context.Context, repo name.Repository) (want *google.Tags, err error) {
	err = backoff(GCRBackoff(), func() error {
		want, err = google.List(repo, c.opt.google...)
		return err
	})()
	return
}

func (c *copier) copyImages(ctx context.Context, oldRepo name.Repository, want *google.Tags) error {
	newRepo, err := c.rename(oldRepo)
	if err != nil {
		return fmt.Errorf("rename failed: %w", err)
	}

	have, err := google.List(newRepo, c.opt.google...)
	if err != nil {
		if !hasStatusCode(err, http.StatusNotFound) {
			return err
		}
		// This is a 404 code, so we just need to copy everything.
		logs.Warn.Printf("failed to list %s: %v", newRepo, err)
		have = &google.Tags{Manifests: map[string]google.ManifestInfo{}}
	}

	// Figure out what we actually need to copy.
	need := diffImages(want.Manifests, have.Manifests)

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(c.opt.jobs)

	// Push everything we need.
	for digest, manifest := range need {
		digest, manifest := digest, manifest

		g.Go(func() error {
			src, err := c.puller.Get(ctx, oldRepo.Digest(digest))
			if err != nil {
				return err
			}

			refs := []name.Reference{}
			for _, tag := range manifest.Tags {
				refs = append(refs, newRepo.Tag(tag))
			}
			if len(refs) == 0 {
				refs = append(refs, newRepo.Digest(digest))
			}

			for _, ref := range refs {
				ref := ref

				if err := c.pusher.Push(ctx, ref, src); err != nil {
					return err
				}
			}

			return nil
		})
	}

	return g.Wait()
}

// Retry temporary errors, 429, and 500+ with backoff.
// TODO: ctx cancellation
func backoff(bo retry.Backoff, f func() error) func() error {
	return func() error {
		p := func(err error) bool {
			b := retry.IsTemporary(err) || hasStatusCode(err, http.StatusTooManyRequests) || isServerError(err)
			if b {
				logs.Warn.Printf("Retrying %v", err)
			}
			return b
		}
		return retry.Retry(f, p, bo)
	}
}

func hasStatusCode(err error, code int) bool {
	if err == nil {
		return false
	}
	var terr *transport.Error
	if errors.As(err, &terr) {
		if terr.StatusCode == code {
			return true
		}
	}
	return false
}

func isServerError(err error) bool {
	if err == nil {
		return false
	}
	var terr *transport.Error
	if errors.As(err, &terr) {
		return terr.StatusCode >= 500
	}
	return false
}

// rename figures out the name of the new repository to copy to, e.g.:
//
// $ gcrane cp -r gcr.io/foo gcr.io/baz
//
// rename("gcr.io/foo/bar") == "gcr.io/baz/bar"
func (c *copier) rename(repo name.Repository) (name.Repository, error) {
	replaced := strings.Replace(repo.String(), c.srcRepo.String(), c.dstRepo.String(), 1)
	return name.NewRepository(replaced, name.StrictValidation)
}

// diffImages returns a map of digests to google.ManifestInfos for images or
// tags that are present in "want" but not in "have".
func diffImages(want, have map[string]google.ManifestInfo) map[string]google.ManifestInfo {
	need := make(map[string]google.ManifestInfo)

	for digest, wantManifest := range want {
		if haveManifest, ok := have[digest]; !ok {
			// Missing the whole image, we need to copy everything.
			need[digest] = wantManifest
		} else {
			missingTags := subtractStringLists(wantManifest.Tags, haveManifest.Tags)
			if len(missingTags) == 0 {
				continue
			}

			// Missing just some tags, add the ones we need to copy.
			todo := wantManifest
			todo.Tags = missingTags
			need[digest] = todo
		}
	}

	return need
}

// subtractStringLists returns a list of strings that are in minuend and not
// in subtrahend; order is unimportant.
func subtractStringLists(minuend, subtrahend []string) []string {
	bSet := toStringSet(subtrahend)
	difference := []string{}

	for _, a := range minuend {
		if _, ok := bSet[a]; !ok {
			difference = append(difference, a)
		}
	}

	return difference
}

func toStringSet(slice []string) map[string]struct{} {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}
	return set
}
