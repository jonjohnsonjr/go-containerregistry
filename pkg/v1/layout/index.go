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
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

var _ v1.ImageIndex = (*layoutIndex)(nil)

type layoutIndex struct {
	path     string
	rawIndex []byte
}

func Index(path string) (*layoutIndex, error) {
	rawIndex, err := ioutil.ReadFile(filepath.Join(path, "index.json"))
	if err != nil {
		return nil, err
	}

	img := &layoutIndex{
		path:     path,
		rawIndex: rawIndex,
	}

	return img, nil
}

func (i *layoutIndex) MediaType() (types.MediaType, error) {
	return types.OCIImageIndex, nil
}

func (i *layoutIndex) Digest() (v1.Hash, error) {
	digest, _, err := v1.SHA256(bytes.NewReader(i.rawIndex))
	return digest, err
}

func (i *layoutIndex) IndexManifest() (*v1.IndexManifest, error) {
	var index v1.IndexManifest
	err := json.Unmarshal(i.rawIndex, &index)
	return &index, err
}

func (i *layoutIndex) RawIndexManifest() ([]byte, error) {
	return i.rawIndex, nil
}

func (i *layoutIndex) Image(h v1.Hash) (v1.Image, error) {
	// Look up the digest in our manifest first to return a better error.
	desc, err := i.findDescriptor(h)
	if err != nil {
		return nil, err
	}

	switch desc.MediaType {
	case types.OCIManifestSchema1, types.DockerManifestSchema2:
		// Expected, keep going.
	default:
		return nil, fmt.Errorf("unexpected media type for %v: %s", h, desc.MediaType)
	}

	img := &layoutImage{
		path: i.path,
		desc: *desc,
	}
	return partial.CompressedToImage(img)
}

func (i *layoutIndex) ImageIndex(h v1.Hash) (v1.ImageIndex, error) {
	// Look up the digest in our manifest first to return a better error.
	desc, err := i.findDescriptor(h)
	if err != nil {
		return nil, err
	}

	switch desc.MediaType {
	case types.OCIImageIndex, types.DockerManifestList:
		// Expected, keep going.
	default:
		return nil, fmt.Errorf("unexpected media type for %v: %s", h, desc.MediaType)
	}

	rawIndex, err := ioutil.ReadFile(filepath.Join(i.path, "blobs", h.Algorithm, h.Hex))
	if err != nil {
		return nil, err
	}

	return &layoutIndex{
		path:     i.path,
		rawIndex: rawIndex,
	}, nil
}

func (i *layoutIndex) findDescriptor(h v1.Hash) (*v1.Descriptor, error) {
	im, err := i.IndexManifest()
	if err != nil {
		return nil, err
	}

	for _, desc := range im.Manifests {
		if desc.Digest == h {
			return &desc, nil
		}
	}

	return nil, fmt.Errorf("could not find descriptor in index.json: %s", h)
}
