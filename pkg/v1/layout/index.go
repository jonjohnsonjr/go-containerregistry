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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

var _ v1.ImageIndex = (*layoutIndex)(nil)

type layoutIndex struct {
	path     Path
	rawIndex []byte
	desc     *v1.Descriptor
}

// ImageIndexFromPath is a convenience function which constructs a Path and returns its v1.ImageIndex.
func ImageIndexFromPath(path string) (v1.ImageIndex, error) {
	lp, err := FromPath(path)
	if err != nil {
		return nil, err
	}
	return lp.ImageIndex()
}

// ImageIndex returns a v1.ImageIndex for the Path.
func (l Path) ImageIndex() (v1.ImageIndex, error) {
	rawIndex, err := ioutil.ReadFile(l.path("index.json"))
	if err != nil {
		return nil, err
	}

	idx := &layoutIndex{
		path:     l,
		rawIndex: rawIndex,
	}

	return idx, nil
}

func (l Path) Manifests() ([]partial.Describable, error) {
	idx, err := l.ImageIndex()
	if err != nil {
		return nil, err
	}
	m, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}
	manifests := []partial.Describable{}
	for _, desc := range m.Manifests {
		child, err := l.child(desc)
		if err != nil {
			return nil, err
		}
		manifests = append(manifests, child)
	}
	return manifests, nil
}

func (i *layoutIndex) MediaType() (types.MediaType, error) {
	if i.desc == nil {
		return types.OCIImageIndex, nil
	}
	return i.desc.MediaType, nil
}

func (i *layoutIndex) Digest() (v1.Hash, error) {
	return partial.Digest(i)
}

func (i *layoutIndex) Size() (int64, error) {
	return partial.Size(i)
}

func (i *layoutIndex) IndexManifest() (*v1.IndexManifest, error) {
	var index v1.IndexManifest
	err := json.Unmarshal(i.rawIndex, &index)
	return &index, err
}

func (i *layoutIndex) RawManifest() ([]byte, error) {
	return i.rawIndex, nil
}

func (i *layoutIndex) Image(h v1.Hash) (v1.Image, error) {
	// Look up the digest in our manifest first to return a better error.
	desc, err := i.findDescriptor(h)
	if err != nil {
		return nil, err
	}

	if !desc.MediaType.IsImage() {
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

	if !desc.MediaType.IsIndex() {
		return nil, fmt.Errorf("unexpected media type for %v: %s", h, desc.MediaType)
	}

	rawIndex, err := i.path.Bytes(h)
	if err != nil {
		return nil, err
	}

	return &layoutIndex{
		desc:     desc,
		path:     i.path,
		rawIndex: rawIndex,
	}, nil
}

func (i *layoutIndex) Blob(h v1.Hash) (io.ReadCloser, error) {
	return i.path.Blob(h)
}

func (i *layoutIndex) findDescriptor(h v1.Hash) (*v1.Descriptor, error) {
	im, err := i.IndexManifest()
	if err != nil {
		return nil, err
	}

	if h == (v1.Hash{}) {
		if len(im.Manifests) != 1 {
			return nil, errors.New("oci layout must contain only a single image to be used with layout.Image")
		}
		return &(im.Manifests)[0], nil
	}

	for _, desc := range im.Manifests {
		if desc.Digest == h {
			return &desc, nil
		}
	}

	return nil, fmt.Errorf("could not find descriptor in index: %s", h)
}

// Descriptor implements partial.withDescriptor.
func (i *layoutIndex) Descriptor() (*v1.Descriptor, error) {
	return i.desc, nil
}

func (l Path) child(desc v1.Descriptor) (partial.Describable, error) {
	if desc.MediaType.IsIndex() {
		rawIndex, err := l.Bytes(desc.Digest)
		if err != nil {
			return nil, err
		}

		return &layoutIndex{
			desc:     &desc,
			path:     l,
			rawIndex: rawIndex,
		}, nil
	}

	if desc.MediaType.IsImage() {
		img := &layoutImage{
			path: l,
			desc: desc,
		}
		return partial.CompressedToImage(img)
	}

	return &compressedBlob{
		path: l,
		desc: desc,
	}, nil
}
