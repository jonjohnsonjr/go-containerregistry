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
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/stream"
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
	t, err := name.NewTag(tag, o.name...)
	if err != nil {
		return nil, fmt.Errorf("parsing tag %q: %v", tag, err)
	}
	return tarball.ImageFromPath(path, &t)
}

// Push pushes the v1.Image img to a registry as dst.
func Push(img v1.Image, dst string, opt ...Option) error {
	o := makeOptions(opt...)
	tag, err := name.ParseReference(dst, o.name...)
	if err != nil {
		return fmt.Errorf("parsing reference %q: %v", dst, err)
	}
	return remote.Write(tag, img, o.remote...)
}

func Upload(path string, dst string, opt ...Option) (string, error) {
	o := makeOptions(opt...)
	repo, err := name.NewRepository(dst, o.name...)
	if err != nil {
		return "", fmt.Errorf("parsing repository %q: %v", dst, err)
	}
	layer, err := uncompressedLayer(path)
	if err != nil {
		return "", err
	}

	if err := remote.WriteLayer(repo, layer, o.remote...); err != nil {
		return "", err
	}

	digest, err := layer.Digest()
	if err != nil {
		return "", err
	}

	return repo.Digest(digest.String()).String(), nil
}

func uncompressedLayer(path string) (v1.Layer, error) {
	if path == "-" {
		return stream.NewLayer(os.Stdin, stream.WithNoCompression), nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return stream.NewLayer(f, stream.WithNoCompression), nil
}
