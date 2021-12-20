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
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// Load reads the tarball at path as a v1.Image.
func Load(path string, opt ...Option) (v1.Image, error) {
	return LoadTag(path, "")
}

// LoadTag reads a tag from the tarball at path as a v1.Image.
// If tag is "", will attempt to read the tarball as a single image.
func LoadTag(path, tag string, opt ...Option) (v1.Image, error) {
	if tag == "" {
		return tarball.ImageFromPath(path, nil)
	}

	o := makeOptions(opt...)
	t, err := name.NewTag(tag, o.Name...)
	if err != nil {
		return nil, fmt.Errorf("parsing tag %q: %w", tag, err)
	}
	return tarball.ImageFromPath(path, &t)
}

// Pushable is an interface that is satisfied by both v1.Image and v1.ImageIndex.
type Pushable interface {
	RawManifest() ([]byte, error)
}

// Push pushes the v1.Image img to a registry as dst.
func Push(p Pushable, dst string, opt ...Option) error {
	o := makeOptions(opt...)
	tag, err := name.ParseReference(dst, o.Name...)
	if err != nil {
		return fmt.Errorf("parsing reference %q: %w", dst, err)
	}

	if img, ok := p.(v1.Image); ok {
		return remote.Write(tag, img, o.Remote...)
	}
	if idx, ok := p.(v1.ImageIndex); ok {
		return remote.WriteIndex(tag, idx, o.Remote...)
	}

	// If it's neither, we can't do anything with it anyway.
	return remote.Put(tag, p, o.Remote...)
}

// Upload pushes the v1.Layer to a given repo.
func Upload(layer v1.Layer, repo string, opt ...Option) error {
	o := makeOptions(opt...)
	ref, err := name.NewRepository(repo, o.Name...)
	if err != nil {
		return fmt.Errorf("parsing repo %q: %w", repo, err)
	}

	return remote.WriteLayer(ref, layer, o.Remote...)
}
