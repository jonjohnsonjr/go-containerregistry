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

package main

import (
	"fmt"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"log"
	"net/http"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/cobra"
)

func main() {
	// Parent command to which all subcommands are added.
	cmds := &cobra.Command{
		Use:   "compass",
		Short: "Interact with OCI image layouts.",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	// TODO: rm
	//  remove an entry from index.json, optionally garbage collecting unreferenced
	//  blobs
	// TODO: gc
	//  garbage collect unreferenced blobs
	for _, cmd := range []cobra.Command{{
		Use:   "freeze",
		Short: "Pull a remote repo and store it in an oci image layout",
		Args:  cobra.ExactArgs(2),
		Run: func(_ *cobra.Command, args []string) {
			freeze(args[0], args[1])
		},
	}, {
		Use:   "thaw",
		Short: "Push the images in an image layout to a remote registry",
		Args:  cobra.ExactArgs(2),
		Run: func(_ *cobra.Command, args []string) {
			thaw(args[0], args[1])
		},
	}, {
		Use:   "ls",
		Short: "List the manifests in a layout",
		Args:  cobra.ExactArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			ls(args[0])
		},
	}} {
		cmd := cmd
		cmds.AddCommand(&cmd)
	}

	if err := cmds.Execute(); err != nil {
		log.Fatalf("error during command execution: %v", err)
	}
}

func freeze(src, path string) {
	lp, err := layout.Write(path, empty.Index)
	if err != nil {
		log.Fatalf("writing image layout %q: %v", path, err)
	}

	repo, err := name.NewRepository(src, name.WeakValidation)
	if err != nil {
		log.Fatalf("parsing repo %q: %v", src, err)
	}
	log.Printf("Pulling %v", repo)

	auth, err := authn.DefaultKeychain.Resolve(repo.Registry)
	if err != nil {
		log.Fatalf("getting creds for %q: %v", repo, err)
	}

	tags, err := remote.List(repo, auth, http.DefaultTransport)
	if err != nil {
		log.Fatalf("reading repo %q: %v", repo, err)
	}

	for _, tag := range tags {
		t := fmt.Sprintf("%s:%s", repo, tag)
		ref, err := name.NewTag(t, name.StrictValidation)
		if err != nil {
			log.Fatalf("parsing tag %q: %v", t, err)
		}
		log.Printf("Pulling %v", ref)
		img, err := remote.Image(ref, remote.WithAuth(auth))
		if err != nil {
			log.Fatalf("reading image %q: %v", ref, err)
		}

		annotations := map[string]string{
			"org.opencontainers.image.ref.name": t,
		}
		if err := lp.AppendImage(img, layout.WithAnnotations(annotations)); err != nil {
			log.Fatalf("writing image %q: %v", path, err)
		}
	}
}

func thaw(path, dst string) {
	repo, err := name.NewRepository(dst, name.WeakValidation)
	if err != nil {
		log.Fatalf("parsing repo %q: %v", dst, err)
	}
	log.Printf("Pushing %v", repo)

	auth, err := authn.DefaultKeychain.Resolve(repo.Registry)
	if err != nil {
		log.Fatalf("getting creds for %q: %v", repo, err)
	}

	lp, err := layout.Read(path)
	if err != nil {
		log.Fatalf("reading image layout %q: %v", path, err)
	}

	ii, err := lp.ImageIndex()
	if err != nil {
		log.Fatalf("accessing index: %v", err)
	}

	manifest, err := ii.IndexManifest()
	if err != nil {
		log.Fatalf("reading image layout manifest %q: %v", path, err)
	}

	for _, desc := range manifest.Manifests {
		// This logic is janky, we'd want smarter rewriting rules.
		source := ""
		for k, v := range desc.Annotations {
			if k == "org.opencontainers.image.ref.name" {
				source = v
			}
		}

		var ref name.Reference
		if source != "" {
			originalTag, err := name.NewTag(source, name.WeakValidation)
			if err == nil {
				// We parsed as a tag, reuse it.
				t := fmt.Sprintf("%s:%s", repo, originalTag.TagStr())
				ref, err = name.NewTag(t, name.StrictValidation)
				if err != nil {
					log.Fatalf("parsing tag %q: %v", t, err)
				}
			}
		}

		if ref == nil {
			d := fmt.Sprintf("%s@%s", repo, desc.Digest)
			ref, err = name.NewDigest(d, name.StrictValidation)
			if err != nil {
				log.Fatalf("parsing digest %q: %v", d, err)
			}
		}
		log.Printf("Pushing %v", ref)

		// TODO: check media type
		img, err := ii.Image(desc.Digest)
		if err != nil {
			log.Fatalf("reading image %q: %v", ref, err)
		}

		if err := remote.Write(ref, img, auth, http.DefaultTransport); err != nil {
			log.Fatalf("writing image %q: %v", ref, err)
		}
	}
}

func ls(path string) {
	lp, err := layout.Read(path)
	if err != nil {
		log.Fatalf("reading layout: %v", err)
	}

	ii, err := lp.ImageIndex()
	if err != nil {
		log.Fatalf("accessing index: %v", err)
	}

	m, err := ii.IndexManifest()
	if err != nil {
		log.Fatalf("reading manifest: %v", err)
	}

	for _, desc := range m.Manifests {
		fmt.Println(desc.Digest, desc.MediaType)
	}
}