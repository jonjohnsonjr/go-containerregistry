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

package cmd

import (
	"fmt"
	"log"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/spf13/cobra"
)

func init() { Root.AddCommand(NewCmdLayout()) }

// NewCmdLayout creates a new cobra.Command for the layout subcommand.
func NewCmdLayout() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "layout",
		Short: "Pull a remote image by reference and store its contents in a tarball",
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Usage()
		},
	}
	cmd.AddCommand(NewCmdLayoutPull(), NewCmdLayoutPush())
	return cmd
}

func NewCmdLayoutPull() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pull",
		Short: "Pull a remote image by reference and store its contents in a tarball",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			src, dst := args[0], args[1]

			ref, err := name.ParseReference(src)
			if err != nil {
				log.Fatal(err)
			}

			desc, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
			if err != nil {
				log.Fatal(err)
			}

			path, err := layout.FromPath(dst)
			if err != nil {
				// TODO: This could be cleaner. We can have an entrypoint that inits the layout
				// if it does not already exist.
				path, err = layout.Write(dst, empty.Index)
				if err != nil {
					log.Fatal(err)
				}
			}

			switch desc.MediaType {
			case types.OCIImageIndex, types.DockerManifestList:
				// Handle indexes separately.
				idx, err := desc.ImageIndex()
				if err != nil {
					log.Fatal(err)
				}
				if err := pullIndex(idx, ref, path); err != nil {
					log.Fatal(err)
				}
			case types.OCIManifestSchema1, types.DockerManifestSchema2:
				// Handle images separately.
				img, err := desc.Image()
				if err != nil {
					log.Fatal(err)
				}
				if err := pullImage(img, ref, path); err != nil {
					log.Fatal(err)
				}
			default:
				log.Fatalf("unexpected mediatype: %s", desc.MediaType)
			}
		},
	}
	return cmd
}

func pullIndex(idx v1.ImageIndex, ref name.Reference, path layout.Path) error {
	m, err := idx.IndexManifest()
	if err != nil {
		return err
	}

	for _, desc := range m.Manifests {
		switch desc.MediaType {
		case types.OCIImageIndex, types.DockerManifestList:
			// Handle indexes separately.
			idx, err := idx.ImageIndex(desc.Digest)
			if err != nil {
				log.Fatal(err)
			}
			if err := pullIndex(idx, ref, path); err != nil {
				return fmt.Errorf("failed to copy index: %v", err)
			}
			if err := path.AppendIndex(idx); err != nil {
				return err
			}
		case types.OCIManifestSchema1, types.DockerManifestSchema2:
			// Handle images separately.
			img, err := idx.Image(desc.Digest)
			if err != nil {
				log.Fatal(err)
			}
			if err := pullImage(img, ref, path); err != nil {
				return fmt.Errorf("failed to copy schema 1 image: %v", err)
			}
		default:
			return fmt.Errorf("unexpected mediatype: %s", desc.MediaType)
		}
	}
	return nil
}

func pullImage(img v1.Image, ref name.Reference, path layout.Path) error {
	return path.AppendImage(img, layout.WithAnnotations(map[string]string{
		"crane.ggcr.dev/ref":    ref.String(),
		"crane.ggcr.dev/pulled": time.Now().Format(time.RFC3339),
	}))
}

func NewCmdLayoutPush() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "push",
		Short: "Push an image layout to a remote index",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			src, dst := args[0], args[1]
			ref, err := name.ParseReference(dst)
			if err != nil {
				log.Fatal(err)
			}
			idx, err := layout.ImageIndexFromPath(src)
			if err != nil {
				log.Fatal(err)
			}

			if err := remote.WriteIndex(ref, idx, remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
				log.Fatal(err)
			}
		},
	}
	return cmd
}
