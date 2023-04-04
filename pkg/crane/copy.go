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

package crane

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/go-containerregistry/internal/legacy"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"golang.org/x/sync/errgroup"
)

// Copy copies a remote image or index from src to dst.
func Copy(src, dst string, opt ...Option) error {
	o := makeOptions(opt...)
	srcRef, err := name.ParseReference(src, o.Name...)
	if err != nil {
		return fmt.Errorf("parsing reference %q: %w", src, err)
	}

	dstRef, err := name.ParseReference(dst, o.Name...)
	if err != nil {
		return fmt.Errorf("parsing reference for %q: %w", dst, err)
	}

	if tag, ok := dstRef.(name.Tag); ok {
		if o.noclobber {
			logs.Progress.Printf("Checking existing tag %v", tag)
			head, err := remote.Head(tag, o.Remote...)
			var terr *transport.Error
			if errors.As(err, &terr) {
				if terr.StatusCode != http.StatusNotFound && terr.StatusCode != http.StatusForbidden {
					return err
				}
			} else if err != nil {
				return err
			}

			if head != nil {
				return fmt.Errorf("refusing to clobber existing tag %s@%s", tag, head.Digest)
			}
		}
	}

	logs.Progress.Printf("Copying from %v to %v", srcRef, dstRef)
	desc, err := remote.Get(srcRef, o.Remote...)
	if err != nil {
		return fmt.Errorf("fetching %q: %w", src, err)
	}

	switch desc.MediaType {
	case types.OCIImageIndex, types.DockerManifestList:
		// Handle indexes separately.
		if o.Platform != nil {
			// If platform is explicitly set, don't copy the whole index, just the appropriate image.
			if err := copyImage(desc, dstRef, o); err != nil {
				return fmt.Errorf("failed to copy image: %w", err)
			}
		} else {
			if err := copyIndex(desc, dstRef, o); err != nil {
				return fmt.Errorf("failed to copy index: %w", err)
			}
		}
	case types.DockerManifestSchema1, types.DockerManifestSchema1Signed:
		// Handle schema 1 images separately.
		if err := legacy.CopySchema1(desc, srcRef, dstRef, o.Remote...); err != nil {
			return fmt.Errorf("failed to copy schema 1 image: %w", err)
		}
	default:
		// Assume anything else is an image, since some registries don't set mediaTypes properly.
		if err := copyImage(desc, dstRef, o); err != nil {
			return fmt.Errorf("failed to copy image: %w", err)
		}
	}

	return nil
}

func copyImage(desc *remote.Descriptor, dstRef name.Reference, o Options) error {
	img, err := desc.Image()
	if err != nil {
		return err
	}
	return remote.Write(dstRef, img, o.Remote...)
}

func copyIndex(desc *remote.Descriptor, dstRef name.Reference, o Options) error {
	idx, err := desc.ImageIndex()
	if err != nil {
		return err
	}
	return remote.WriteIndex(dstRef, idx, o.Remote...)
}

// CopyRepository copies every tag from src to dst.
func CopyRepository(src, dst string, opt ...Option) error {
	o := makeOptions(opt...)

	srcRepo, err := name.NewRepository(src, o.Name...)
	if err != nil {
		return err
	}

	srcOpts := o.Remote
	auth := o.auth
	if auth == nil {
		auth, err = o.Keychain.Resolve(srcRepo)
		if err != nil {
			return err
		}
	}
	// TODO: remote.NewPuller
	scopes := []string{srcRepo.Scope(transport.PullScope)}
	tr, err := transport.NewWithContext(o.ctx, srcRepo.Registry, auth, o.transport, scopes)
	if err != nil {
		return err
	}
	srcOpts = append(srcOpts, remote.WithTransport(tr))

	ignoredTags := map[string]struct{}{}
	if o.noclobber {
		have, err := ListTags(dst, opt...)
		if err != nil {
			var terr *transport.Error
			if errors.As(err, &terr) {
				// Some registries create repository on first push, so listing tags will fail.
				// If we see 404 or 403, assume we failed because the repository hasn't been created yet.
				if !(terr.StatusCode == http.StatusNotFound || terr.StatusCode == http.StatusForbidden) {
					return err
				}
			} else {
				return err
			}
		}
		for _, tag := range have {
			ignoredTags[tag] = struct{}{}
		}
	}

	pusher, err := remote.NewPusher(o.Remote...)
	if err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(o.ctx)
	g.SetLimit(o.jobs)

	next := ""
	for {
		tags, err := remote.ListPage(srcRepo, next, srcOpts...)
		if err != nil {
			return err
		}

		for _, tag := range tags.Tags {
			tag := tag

			if err := context.Cause(ctx); err != nil {
				return err
			}

			if o.noclobber {
				if _, ok := ignoredTags[tag]; ok {
					logs.Progress.Printf("Skipping %s (already exists)", tag)
					continue
				}
			}

			g.Go(func() error {
				srcTag, err := name.ParseReference(src+":"+tag, o.Name...)
				if err != nil {
					return fmt.Errorf("failed to parse tag: %w", err)
				}
				dstTag, err := name.ParseReference(dst+":"+tag, o.Name...)
				if err != nil {
					return fmt.Errorf("failed to parse tag: %w", err)
				}

				logs.Progress.Printf("Fetching %s", srcTag)
				desc, err := remote.Get(srcTag, srcOpts...)
				if err != nil {
					return err
				}

				logs.Progress.Printf("Pushing %s", dstTag)
				return pusher.Push(ctx, dstTag, desc)
			})
		}

		if tags.Next == "" {
			break
		}
		next = tags.Next
	}

	return g.Wait()
}
