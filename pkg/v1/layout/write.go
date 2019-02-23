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
func Append(p string, img v1.Image) error {
	// Write the config.
	cfgName, err := img.ConfigName()
	if err != nil {
		return err
	}
	cfgBlob, err := img.RawConfigFile()
	if err != nil {
		return err
	}
	if err := writeBlob(p, cfgName, ioutil.NopCloser(bytes.NewReader(cfgBlob))); err != nil {
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
	if err := writeBlob(p, d, ioutil.NopCloser(bytes.NewReader(manifest))); err != nil {
		return err
	}

	// TODO: This just writes a singleton image index, we should not do that.
	// TODO: Index(p) || empty.Index
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

func Write(p string, ii v1.ImageIndex) error {
	// Always just write oci-layout file, since it's small.
	if err := writeFile(p, "oci-layout", []byte(layoutFile)); err != nil {
		return err
	}

	rm, err := ii.RawIndexManifest()
	if err != nil {
		return err
	}

	return writeFile(p, "index.json", rawIndex)
}
