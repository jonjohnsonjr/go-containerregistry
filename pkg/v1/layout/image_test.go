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
	"testing"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/google/go-containerregistry/pkg/v1/validate"
)

var (
	manifestDigest = v1.Hash{
		Algorithm: "sha256",
		Hex:       "eebff607b1628d67459b0596643fc07de70d702eccf030f0bc7bb6fc2b278650",
	}
	indexDigest = v1.Hash{
		Algorithm: "sha256",
		Hex:       "05f95b26ed10668b7183c1e2da98610e91372fa9f510046d4ce5812addad86b5",
	}
	bogusDigest = v1.Hash{
		Algorithm: "sha256",
		Hex:       "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
	}
	bogusPath = "testdata/does_not_exist"
	testPath  = "testdata/test_index"
)

func TestImage(t *testing.T) {
	configDigest := v1.Hash{
		Algorithm: "sha256",
		Hex:       "6e0b05049ed9c17d02e1a55e80d6599dbfcce7f4f4b022e3c673e685789c470e",
	}
	img, err := Image(testPath, manifestDigest)
	if err != nil {
		t.Fatalf("Image() = %v", err)
	}

	if err := validate.Image(img); err != nil {
		t.Fatalf("validate.Image() = %v", err)
	}

	mt, err := img.MediaType()
	if err != nil {
		t.Fatalf("MediaType() = %v", err)
	}

	if got, want := mt, types.OCIManifestSchema1; got != want {
		t.Fatalf("MediaType(); want: %v got: %v", want, got)
	}

	cfg, err := img.LayerByDigest(configDigest)
	if err != nil {
		t.Fatalf("LayerByDigest(%s) = %v", configDigest, err)
	}

	cfgName, err := img.ConfigName()
	if err != nil {
		t.Fatalf("ConfigName() = %v", err)
	}

	cfgDigest, err := cfg.Digest()
	if err != nil {
		t.Fatalf("cfg.Digest() = %v", err)
	}

	if got, want := cfgDigest, cfgName; got != want {
		t.Fatalf("ConfigName(); want: %v got: %v", want, got)
	}
}

func TestImageErrors(t *testing.T) {
	img, err := Image(testPath, manifestDigest)
	if err != nil {
		t.Fatalf("Image() = %v", err)
	}

	if _, err := img.LayerByDigest(bogusDigest); err == nil {
		t.Fatalf("LayerByDigest(%s) = nil, expected err", bogusDigest)
	}

	if _, err := Image(testPath, bogusDigest); err == nil {
		t.Fatalf("Image(%s) = nil, expected err", bogusDigest)
	}

	if _, err := Image(bogusPath, bogusDigest); err == nil {
		t.Fatalf("Image(%s, %s) = nil, expected err", bogusPath, bogusDigest)
	}
}
