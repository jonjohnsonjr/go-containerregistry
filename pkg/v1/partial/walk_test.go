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

package partial_test

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestWalk(t *testing.T) {
	idx, err := random.Index(1024, 3, 2)
	if err != nil {
		t.Fatal(err)
	}

	layer, err := random.Layer(1000, types.OCILayer)
	if err != nil {
		t.Fatal(err)
	}
	child := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
		Add: layer,
	})
	idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
		Add: child,
	})

	i, ii, l := 0, 0, 0
	w := &partial.Walker{
		Index: func(v1.ImageIndex) error {
			ii++
			return nil
		},
		Image: func(v1.Image) error {
			i++
			return nil
		},
		Layer: func(v1.Layer) error {
			l++
			return nil
		},
	}

	if err := partial.Walk(idx, w.Func); err != nil {
		t.Fatal(err)
	}

	if got, want := ii, 2; got != want {
		t.Errorf("wrong number of indexes: %d != %d", got, want)
	}
	if got, want := i, 2; got != want {
		t.Errorf("wrong number of images: %d != %d", got, want)
	}
	if got, want := l, 7; got != want {
		t.Errorf("wrong number of layers: %d != %d", got, want)
	}
}
