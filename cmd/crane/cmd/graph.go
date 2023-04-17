// Copyright 2023 Google LLC All Rights Reserved.
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
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/spf13/cobra"
)

// NewCmdGraph creates a new cobra.Command for the graph subcommand.
func NewCmdGraph(options *[]crane.Option) *cobra.Command {
	return &cobra.Command{
		Use:     "graph IMAGE",
		Short:   "Produce dot representing a given image.",
		Example: "crane graph ubuntu | dot TODO",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			src := args[0]
			ref, err := name.ParseReference(src)
			if err != nil {
				return err
			}
			desc, err := remote.Get(ref)
			if err != nil {
				return err
			}

			fmt.Fprintf(os.Stdout, "digraph g {\n")
			fmt.Fprintf(os.Stdout, "  rankdir=LR;\n")

			fmt.Fprintf(os.Stdout, "  %q [shape=%q, style=%q];\n", truncate(desc.Digest.String()), "note", "bold")

			if tag, ok := ref.(name.Tag); ok {
				tagged(tag.String(), desc.Digest.String())
			}

			descs := []*remote.Descriptor{desc}

			for _, t := range []string{"att", "sig", "sbom"} {
				tag := strings.Replace(desc.Digest.String(), ":", "-", 1) + "." + t
				refs, err := remote.Get(ref.Context().Tag(tag))
				var terr *transport.Error
				if errors.As(err, &terr) {
					if terr.StatusCode == http.StatusNotFound {
						logs.Debug.Printf("")
						continue
					}
				} else if err != nil {
					return err
				}
				display := strings.Replace(truncate(desc.Digest.String()), ":", "-", 1) + "..." + t
				tagged(display, refs.Digest.String())
				subject(refs.Digest.String(), desc.Digest.String())
				descs = append(descs, refs)
			}

			for _, desc := range descs {
				if desc.MediaType.IsImage() {
					img, err := desc.Image()
					if err != nil {
						return err
					}

					if err := image(desc.Digest.String(), img); err != nil {
						return err
					}
				} else {
					idx, err := desc.ImageIndex()
					if err != nil {
						return err
					}

					if err := index(desc.Digest.String(), idx); err != nil {
						return err
					}
				}

				refs, err := remote.Referrers(ref.Context().Digest(desc.Digest.String()))
				if err != nil {
					return err
				}

				for _, ref := range refs.Manifests {
					fmt.Fprintf(os.Stdout, "  %q -> %q;\n", ref.Digest.String(), desc.Digest.String())
				}
			}

			fmt.Fprintf(os.Stdout, "}\n")
			return nil
		},
	}
}

func image(src string, img v1.Image) error {
	m, err := img.Manifest()
	if err != nil {
		return err
	}

	configBlob(src, m.Config.Digest.String())

	for _, l := range m.Layers {
		blob(src, l.Digest.String())
	}

	if m.Subject != nil {
		subject(src, m.Subject.Digest.String())
	}

	return nil
}

func index(src string, idx v1.ImageIndex) error {
	m, err := idx.IndexManifest()
	if err != nil {
		return err
	}

	children, err := partial.Manifests(idx)
	if err != nil {
		return err
	}

	for _, child := range children {
		dig, err := child.Digest()
		if err != nil {
			return err
		}

		manifest(src, dig.String())

		if img, ok := child.(v1.Image); ok {
			if err := image(dig.String(), img); err != nil {
				return err
			}
		} else if idx, ok := child.(v1.ImageIndex); ok {
			if err := index(dig.String(), idx); err != nil {
				return err
			}
		} else {
		}
	}

	if m.Subject != nil {
		subject(src, m.Subject.Digest.String())
	}

	return nil
}

var truncLength = 8 + len("sha256:")

func truncate(src string) string {
	if strings.HasPrefix(src, "sha256:") && len(src) > truncLength {
		return src[0:truncLength]
	}
	return src
}

func node(dst, shape string) {
	fmt.Fprintf(os.Stdout, "  %q [shape=%q];\n", truncate(dst), shape)
}

func subject(src, dst string) {
	node(dst, "note")
	fmt.Fprintf(os.Stdout, "  %q -> %q [style=%q];\n", truncate(src), truncate(dst), "dashed")
}

func tagged(src, dst string) {
	node(dst, "note")
	fmt.Fprintf(os.Stdout, "  %q -> %q [style=%q];\n", truncate(src), truncate(dst), "dotted")
}

func manifest(src, dst string) {
	node(dst, "note")
	fmt.Fprintf(os.Stdout, "  %q -> %q;\n", truncate(src), truncate(dst))
}

func configBlob(src, dst string) {
	node(dst, "septagon")
	fmt.Fprintf(os.Stdout, "  %q -> %q;\n", truncate(src), truncate(dst))
}

func blob(src, dst string) {
	node(dst, "folder")
	fmt.Fprintf(os.Stdout, "  %q -> %q;\n", truncate(src), truncate(dst))
}
