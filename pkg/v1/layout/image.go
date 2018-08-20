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
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

type layoutImage struct {
	path        string
	rawManifest []byte
}

var _ partial.CompressedImageCore = (*layoutImage)(nil)

func Image(path string, hash v1.Hash) (v1.Image, error) {
	rawManifest, err := ioutil.ReadFile(filepath.Join(path, "blobs", hash.Algorithm, hash.Hex))
	if err != nil {
		return nil, err
	}

	img := &layoutImage{
		path:        path,
		rawManifest: rawManifest,
	}

	return partial.CompressedToImage(img)
}

func (li *layoutImage) MediaType() (types.MediaType, error) {
	return types.OCIManifestSchema1, nil
}

func (li *layoutImage) Manifest() (*v1.Manifest, error) {
	return partial.Manifest(li)
}

func (li *layoutImage) RawManifest() ([]byte, error) {
	return li.rawManifest, nil
}

func (li *layoutImage) RawConfigFile() ([]byte, error) {
	manifest, err := li.Manifest()
	if err != nil {
		return nil, err
	}

	cfg := manifest.Config.Digest

	return ioutil.ReadFile(filepath.Join(li.path, "blobs", cfg.Algorithm, cfg.Hex))
}

func (li *layoutImage) BlobSet() (map[v1.Hash]struct{}, error) {
	return partial.BlobSet(li)
}

func (li *layoutImage) LayerByDigest(digest v1.Hash) (partial.CompressedLayer, error) {
	manifest, err := li.Manifest()
	if err != nil {
		return nil, err
	}

	for _, desc := range manifest.Layers {
		if desc.Digest == digest {
			// We assume that all these layers are compressed, which is probably not
			// safe to assume. It will take some restructuring to make that work, so
			// just return an error for now if we encounter unexpected layers.
			if err := checkLayerMediaType(desc); err != nil {
				return nil, err
			}

			return partial.CompressedLayer(&compressedBlob{
				path: li.path,
				desc: desc,
			}), nil
		}
	}

	return nil, fmt.Errorf("could not find layer in image: %s", digest)
}

func checkLayerMediaType(desc v1.Descriptor) error {
	switch desc.MediaType {
	case types.OCILayer:
	case types.DockerLayer:
	default:
		return fmt.Errorf("unexpected layer media type: %s for layer: %s", desc.MediaType, desc.Digest)
	}

	return nil
}

type compressedBlob struct {
	path string
	desc v1.Descriptor
}

func (b *compressedBlob) Digest() (v1.Hash, error) {
	return b.desc.Digest, nil
}

func (b *compressedBlob) Compressed() (io.ReadCloser, error) {
	hash := b.desc.Digest
	return os.Open(filepath.Join(b.path, "blobs", hash.Algorithm, hash.Hex))
}

func (b *compressedBlob) Size() (int64, error) {
	return b.desc.Size, nil
}
