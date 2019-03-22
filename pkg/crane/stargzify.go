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
	"bytes"
	"fmt"
	"log"
	"net/http"

	"github.com/golang/build/crfs/stargz"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/spf13/cobra"
)

func init() { Root.AddCommand(NewCmdStargzify()) }

// NewCmdStargzify creates a new cobra.Command for the stargzify subcommand.
func NewCmdStargzify() *cobra.Command {
	return &cobra.Command{
		Use:   "stargzify",
		Short: "Efficiently stargzify a remote image from src to dst",
		Args:  cobra.ExactArgs(2),
		Run:   doStargzify,
	}
}

func doStargzify(_ *cobra.Command, args []string) {
	src, dst := args[0], args[1]
	srcRef, err := name.ParseReference(src, name.WeakValidation)
	if err != nil {
		log.Fatal(err)
	}

	// Pull source image
	srcImg, err := remote.Image(srcRef, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		log.Fatal(err)
	}

	// grab src config, clear the layer info from the config file
	srcCfg, err := srcImg.ConfigFile()
	if err != nil {
		log.Fatal(err)
	}
	srcCfg.RootFS.DiffIDs = []v1.Hash{}
	srcCfg.History = []v1.History{}

	// Use empty image with the rest of src's config file as a base
	img, err := mutate.ConfigFile(empty.Image, srcCfg)
	if err != nil {
		log.Fatal(err)
	}

	layers, err := srcImg.Layers()
	if err != nil {
		log.Fatal(err)
	}

	// stargzify all src's layers
	b := new(bytes.Buffer)
	w := stargz.NewWriter(b)
	for _, layer := range layers {
		cr, err := layer.Compressed()
		if err != nil {
			log.Fatal(err)
		}
		defer cr.Close()
		if err := w.AppendTar(cr); err != nil {
			log.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		log.Fatal(err)
	}

	// add that as a single layer
	l, err := tarball.LayerFromReader(b)
	if err != nil {
		log.Fatal(err)
	}
	img, err = mutate.Append(img, mutate.Addendum{
		Layer: l,
		History: v1.History{
			CreatedBy: fmt.Sprintf("crane stargzify %s", src),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// push the image to dst
	dstRef, err := name.ParseReference(dst, name.WeakValidation)
	if err != nil {
		log.Fatal(err)
	}
	dstAuth, err := authn.DefaultKeychain.Resolve(dstRef.Context().Registry)
	if err != nil {
		log.Fatal(err)
	}

	if err := remote.Write(dstRef, img, dstAuth, http.DefaultTransport); err != nil {
		log.Fatal(err)
	}
}
