// Copyright 2021 Google LLC All Rights Reserved.
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

package partial

import (
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// TODO: do we care for this?
// var SkipWalk = errors.New("skip this object")

// Walker makes it slightly easier to implement WalkFunc by casting
// partial.Describable to an Image, ImageIndex, or Layer (if it can), and
// calling the given func. If a func is unset, the object will get dropped.
type Walker struct {
	Image       func(v1.Image) error
	Index       func(v1.ImageIndex) error
	Layer       func(v1.Layer) error
	Describable func(Describable) error
}

// Func implements WalkFunc.
func (w *Walker) Func(d Describable) error {
	switch t := d.(type) {
	case v1.ImageIndex:
		if f := w.Index; f != nil {
			return f(t)
		}
	case v1.Image:
		if f := w.Image; f != nil {
			return f(t)
		}
	case v1.Layer:
		if f := w.Layer; f != nil {
			return f(t)
		}
	default:
		if f := w.Describable; f != nil {
			return f(t)
		}
	}

	return nil
}

// WalkFunc is the type of the function called for each object visited by Walk.
// This implements a similar API to filepath.Walk.
type WalkFunc = func(Describable) error

// Walk performs a depth-first post-order traversal of the given object.
// v1.ImageIndex will recursively walk its children.
// v1.Image will walk its layers.
// v1.Layer and anything else will just call the given WalkFunc.
func Walk(d Describable, f WalkFunc) error {
	walker := &Walker{
		Index:       walkIndex(f),
		Image:       walkImage(f),
		Layer:       walkLayer(f),
		Describable: f,
	}
	return walker.Func(d)
}

func walkLayer(f WalkFunc) func(v1.Layer) error {
	return func(l v1.Layer) error {
		return f(l)
	}
}

func walkImage(f WalkFunc) func(v1.Image) error {
	return func(img v1.Image) error {
		layers, err := img.Layers()
		if err != nil {
			return err
		}

		for _, layer := range layers {
			if err := f(layer); err != nil {
				return err
			}
		}

		return f(img)
	}
}

type withLayer interface {
	Layer(v1.Hash) (v1.Layer, error)
}

func walkIndex(f WalkFunc) func(idx v1.ImageIndex) error {
	return func(idx v1.ImageIndex) error {
		m, err := idx.IndexManifest()
		if err != nil {
			return err
		}

		for _, desc := range m.Manifests {
			switch desc.MediaType {
			case types.OCIImageIndex, types.DockerManifestList:
				ii, err := idx.ImageIndex(desc.Digest)
				if err != nil {
					return err
				}
				if err := walkIndex(f)(ii); err != nil {
					return err
				}
			case types.OCIManifestSchema1, types.DockerManifestSchema2:
				img, err := idx.Image(desc.Digest)
				if err != nil {
					return err
				}
				if err := walkImage(f)(img); err != nil {
					return err
				}
			default:
				// Workaround for #819.
				if wl, ok := idx.(withLayer); ok {
					layer, err := wl.Layer(desc.Digest)
					if err != nil {
						return err
					}
					if err := f(layer); err != nil {
						return err
					}
				} else {
					// TODO: This is Unexpected.
				}
			}
		}

		return f(idx)
	}
}
