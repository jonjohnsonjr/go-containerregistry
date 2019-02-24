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

package layout

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"golang.org/x/sync/errgroup"
)

var layoutFile = `{
    "imageLayoutVersion": "1.0.0"
}`

// Write the contents of the image to the provided directory, in the compressed format.
// The contents are written in the following format:
// At the top level, there is:
//   One oci-layout file containing the version of this image-layout.
//   One index.json file containing information about (potentially) several images.
// Under blobs/, there is:
//   One file for each layer, named after the layer's SHA.
//   One file for the config blob, named after its SHA.
//
// https://github.com/opencontainers/image-spec/blob/master/image-layout.md
func Append(path string, img v1.Image) error {
	// TODO: Options for Annotations and URLs.
	var ii v1.ImageIndex

	ii, err := Index(path)
	if os.IsNotExist(err) {
		if err := writeFile(path, "oci-layout", []byte(layoutFile)); err != nil {
			return err
		}
		ii = empty.Index
	}

	if err := writeImage(path, img); err != nil {
		return err
	}

	mt, err := img.MediaType()
	if err != nil {
		return err
	}

	d, err := img.Digest()
	if err != nil {
		return err
	}

	manifest, err := img.RawManifest()
	if err != nil {
		return err
	}

	index, err := ii.IndexManifest()
	if err != nil {
		return err
	}

	index.Manifests = append(index.Manifests, v1.Descriptor{
		MediaType: mt,
		Size:      int64(len(manifest)),
		Digest:    d,
	})

	rawIndex, err := json.MarshalIndent(index, "", "   ")
	if err != nil {
		return err
	}

	return writeFile(path, "index.json", rawIndex)
}

func writeFile(path string, name string, data []byte) error {
	if err := os.MkdirAll(path, os.ModePerm); err != nil && !os.IsExist(err) {
		return err
	}

	return ioutil.WriteFile(filepath.Join(path, name), data, os.ModePerm)
}

func writeBlob(path string, hash v1.Hash, r io.ReadCloser) error {
	dir := filepath.Join(path, "blobs", hash.Algorithm)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil && !os.IsExist(err) {
		return err
	}

	w, err := os.Create(filepath.Join(dir, hash.Hex))
	if os.IsExist(err) {
		// Blob already exists, that's fine.
		return nil
	} else if err != nil {
		return err
	}
	defer w.Close()

	_, err = io.Copy(w, r)
	return err
}

// TODO: For streaming layers we should write to a tmp file then Rename to the
// final digest.
func writeLayer(path string, layer v1.Layer) error {
	d, err := layer.Digest()
	if err != nil {
		return err
	}

	r, err := layer.Compressed()
	if err != nil {
		return err
	}

	return writeBlob(path, d, r)
}

// TODO: Refactor things so that this code can be shared with remote.Write?
func writeImage(path string, img v1.Image) error {
	layers, err := img.Layers()
	if err != nil {
		return err
	}

	// Write the layers concurrently.
	var g errgroup.Group
	for _, layer := range layers {
		layer := layer
		g.Go(func() error {
			return writeLayer(path, layer)
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	// Write the config.
	cfgName, err := img.ConfigName()
	if err != nil {
		return err
	}
	cfgBlob, err := img.RawConfigFile()
	if err != nil {
		return err
	}
	if err := writeBlob(path, cfgName, ioutil.NopCloser(bytes.NewReader(cfgBlob))); err != nil {
		return err
	}

	// Write the img manifest.
	d, err := img.Digest()
	if err != nil {
		return err
	}
	manifest, err := img.RawManifest()
	if err != nil {
		return err
	}

	return writeBlob(path, d, ioutil.NopCloser(bytes.NewReader(manifest)))
}

func writeIndex(path string, indexFile string, ii v1.ImageIndex) error {
	// Always just write oci-layout file, since it's small.
	if err := writeFile(path, "oci-layout", []byte(layoutFile)); err != nil {
		return err
	}

	index, err := ii.IndexManifest()
	if err != nil {
		return err
	}

	for _, desc := range index.Manifests {
		switch desc.MediaType {
		case types.OCIImageIndex, types.DockerManifestList:
			ii, err := ii.ImageIndex(desc.Digest)
			if err != nil {
				return err
			}

			indexFile := filepath.Join("blobs", desc.Digest.Algorithm, desc.Digest.Hex)
			if err := writeIndex(path, indexFile, ii); err != nil {
				return err
			}
		case types.OCIManifestSchema1, types.DockerManifestSchema2:
			img, err := ii.Image(desc.Digest)
			if err != nil {
				return err
			}
			if err := writeImage(path, img); err != nil {
				return err
			}
		}
	}

	rawIndex, err := ii.RawIndexManifest()
	if err != nil {
		return err
	}

	return writeFile(path, indexFile, rawIndex)
}

func Write(path string, ii v1.ImageIndex) error {
	// Always just write oci-layout file, since it's small.
	if err := writeFile(path, "oci-layout", []byte(layoutFile)); err != nil {
		return err
	}

	return writeIndex(path, "index.json", ii)
}
