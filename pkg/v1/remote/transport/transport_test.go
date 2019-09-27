// Copyright 2019 Google LLC All Rights Reserved.
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

package transport_test

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/validate"
)

// This uses remote to exercise the underlying transport.
func TestTransport(t *testing.T) {
	img, err := random.Image(1024, 10)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}

	s := httptest.NewServer(registry.New())
	defer s.Close()
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	dst := fmt.Sprintf("%s/some/path@%s", u.Host, digest)
	ref, err := name.NewDigest(dst)
	if err != nil {
		t.Fatal(err)
	}

	if err := remote.Write(ref, img); err != nil {
		t.Fatalf("failed to Write: %v", err)
	}

	rmt, err := remote.Image(ref)
	if err != nil {
		t.Fatalf("remote.Image() = %v", err)
	}

	if err := validate.Image(rmt); err != nil {
		t.Errorf("Validating remote: %v", err)
	}
}
