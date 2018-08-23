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
	"github.com/google/go-containerregistry/pkg/v1/v1util"
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
func Write(p string, img v1.Image) error {
	// Write oci-layout file.
	if err := writeFile(p, "oci-layout", []byte(layoutFile)); err != nil {
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
	if err := writeBlob(p, cfgName, v1util.NopReadCloser(bytes.NewReader(cfgBlob))); err != nil {
		return err
	}

	// Write the layers.
	layers, err := img.Layers()
	if err != nil {
		return err
	}

	for _, l := range layers {
		d, err := l.Digest()
		if err != nil {
			return err
		}

		r, err := l.Compressed()
		if err != nil {
			return err
		}

		if err := writeBlob(p, d, r); err != nil {
			return err
		}
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
	if err := writeBlob(p, d, v1util.NopReadCloser(bytes.NewReader(manifest))); err != nil {
		return err
	}

	// Write index.json, currently just points to a single image.
	mt, err := img.MediaType()
	if err != nil {
		return err
	}

	index := v1.IndexManifest{
		SchemaVersion: 2,
		Manifests: []v1.Descriptor{{
			MediaType: mt,
			Size:      int64(len(manifest)),
			Digest:    d,
		}},
	}

	rawIndex, err := json.MarshalIndent(index, "", "   ")
	if err != nil {
		return err
	}

	return writeFile(p, "index.json", rawIndex)
}

func writeFile(path string, name string, data []byte) error {
	if err := os.MkdirAll(path, os.ModePerm); err != nil {
		return err
	}

	return ioutil.WriteFile(filepath.Join(path, name), data, os.ModePerm)
}

func writeBlob(path string, hash v1.Hash, r io.ReadCloser) error {
	dir := filepath.Join(path, "blobs", hash.Algorithm)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return err
	}

	// TODO: Ignore already exists, since that's okay.
	w, err := os.Create(filepath.Join(dir, hash.Hex))
	if err != nil {
		return err
	}
	defer w.Close()

	// TODO: Do we need to do this in a goroutine?
	_, err = io.Copy(w, r)
	return err
}
