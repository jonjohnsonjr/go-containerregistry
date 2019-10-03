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

package tarball_test

import (
	"archive/tar"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/internal/compare"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/google/go-containerregistry/pkg/v1/validate"
)

func TestWrite(t *testing.T) {
	// Make a tempfile for tarball writes.
	fp, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatalf("Error creating temp file.")
	}
	t.Log(fp.Name())
	defer fp.Close()
	defer os.Remove(fp.Name())

	// Make a random image
	randImage, err := random.Image(256, 8)
	if err != nil {
		t.Fatalf("Error creating random image.")
	}
	tag, err := name.NewTag("gcr.io/foo/bar:latest", name.StrictValidation)
	if err != nil {
		t.Fatalf("Error creating test tag.")
	}
	if err := tarball.WriteToFile(fp.Name(), tag, randImage); err != nil {
		t.Fatalf("Unexpected error writing tarball: %v", err)
	}

	// Make sure the image is valid and can be loaded.
	// Load it both by nil and by its name.
	for _, it := range []*name.Tag{nil, &tag} {
		tarImage, err := tarball.ImageFromPath(fp.Name(), it)
		if err != nil {
			t.Fatalf("Unexpected error reading tarball: %v", err)
		}

		if err := validate.Image(tarImage); err != nil {
			t.Errorf("validate.Image: %v", err)
		}

		if err := compare.Images(randImage, tarImage); err != nil {
			t.Errorf("compare.Images: %v", err)
		}
	}

	// Try loading a different tag, it should error.
	fakeTag, err := name.NewTag("gcr.io/notthistag:latest", name.StrictValidation)
	if err != nil {
		t.Fatalf("Error generating tag: %v", err)
	}
	if _, err := tarball.ImageFromPath(fp.Name(), &fakeTag); err == nil {
		t.Errorf("Expected error loading tag %v from image", fakeTag)
	}
}

func TestMultiWriteSameImage(t *testing.T) {
	// Make a tempfile for tarball writes.
	fp, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatalf("Error creating temp file.")
	}
	t.Log(fp.Name())
	defer fp.Close()
	defer os.Remove(fp.Name())

	// Make a random image
	randImage, err := random.Image(256, 8)
	if err != nil {
		t.Fatalf("Error creating random image.")
	}

	// Make two tags that point to the random image above.
	tag1, err := name.NewTag("gcr.io/foo/bar:latest", name.StrictValidation)
	if err != nil {
		t.Fatalf("Error creating test tag1.")
	}
	tag2, err := name.NewTag("gcr.io/baz/bat:latest", name.StrictValidation)
	if err != nil {
		t.Fatalf("Error creating test tag2.")
	}
	dig3, err := name.NewDigest("gcr.io/baz/baz@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", name.StrictValidation)
	if err != nil {
		t.Fatalf("Error creating test dig3.")
	}
	refToImage := make(map[name.Reference]v1.Image)
	refToImage[tag1] = randImage
	refToImage[tag2] = randImage
	refToImage[dig3] = randImage

	// Write the images with both tags to the tarball
	if err := tarball.MultiRefWriteToFile(fp.Name(), refToImage); err != nil {
		t.Fatalf("Unexpected error writing tarball: %v", err)
	}
	for ref := range refToImage {
		tag, ok := ref.(name.Tag)
		if !ok {
			continue
		}

		tarImage, err := tarball.ImageFromPath(fp.Name(), &tag)
		if err != nil {
			t.Fatalf("Unexpected error reading tarball: %v", err)
		}

		if err := validate.Image(tarImage); err != nil {
			t.Errorf("validate.Image: %v", err)
		}

		if err := compare.Images(randImage, tarImage); err != nil {
			t.Errorf("compare.Images: %v", err)
		}
	}
}

func TestMultiWriteDifferentImages(t *testing.T) {
	// Make a tempfile for tarball writes.
	fp, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatalf("Error creating temp file.")
	}
	t.Log(fp.Name())
	defer fp.Close()
	defer os.Remove(fp.Name())

	// Make a random image
	randImage1, err := random.Image(256, 8)
	if err != nil {
		t.Fatalf("Error creating random image 1.")
	}

	// Make another random image
	randImage2, err := random.Image(256, 8)
	if err != nil {
		t.Fatalf("Error creating random image 2.")
	}

	// Make another random image
	randImage3, err := random.Image(256, 8)
	if err != nil {
		t.Fatalf("Error creating random image 3.")
	}

	// Create two tags, one pointing to each image created.
	tag1, err := name.NewTag("gcr.io/foo/bar:latest", name.StrictValidation)
	if err != nil {
		t.Fatalf("Error creating test tag1.")
	}
	tag2, err := name.NewTag("gcr.io/baz/bat:latest", name.StrictValidation)
	if err != nil {
		t.Fatalf("Error creating test tag2.")
	}
	dig3, err := name.NewDigest("gcr.io/baz/baz@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", name.StrictValidation)
	if err != nil {
		t.Fatalf("Error creating test dig3.")
	}
	refToImage := make(map[name.Reference]v1.Image)
	refToImage[tag1] = randImage1
	refToImage[tag2] = randImage2
	refToImage[dig3] = randImage3

	// Write both images to the tarball.
	if err := tarball.MultiRefWriteToFile(fp.Name(), refToImage); err != nil {
		t.Fatalf("Unexpected error writing tarball: %v", err)
	}
	for ref, img := range refToImage {
		tag, ok := ref.(name.Tag)
		if !ok {
			continue
		}

		tarImage, err := tarball.ImageFromPath(fp.Name(), &tag)
		if err != nil {
			t.Fatalf("Unexpected error reading tarball: %v", err)
		}

		if err := validate.Image(tarImage); err != nil {
			t.Errorf("validate.Image: %v", err)
		}

		if err := compare.Images(img, tarImage); err != nil {
			t.Errorf("compare.Images: %v", err)
		}
	}
}

func TestWriteForeignLayers(t *testing.T) {
	// Make a tempfile for tarball writes.
	fp, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatalf("Error creating temp file.")
	}
	t.Log(fp.Name())
	defer fp.Close()
	defer os.Remove(fp.Name())

	// Make a random image
	randImage, err := random.Image(256, 1)
	if err != nil {
		t.Fatalf("Error creating random image.")
	}
	tag, err := name.NewTag("gcr.io/foo/bar:latest", name.StrictValidation)
	if err != nil {
		t.Fatalf("Error creating test tag.")
	}
	randLayer, err := random.Layer(512, types.DockerForeignLayer)
	if err != nil {
		t.Fatalf("random.Layer: %v", err)
	}
	img, err := mutate.Append(randImage, mutate.Addendum{
		Layer: randLayer,
		URLs: []string{
			"example.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tarball.WriteToFile(fp.Name(), tag, img); err != nil {
		t.Fatalf("Unexpected error writing tarball: %v", err)
	}

	tarImage, err := tarball.ImageFromPath(fp.Name(), &tag)
	if err != nil {
		t.Fatalf("Unexpected error reading tarball: %v", err)
	}

	if err := validate.Image(tarImage); err != nil {
		t.Fatalf("validate.Image(): %v", err)
	}

	m, err := tarImage.Manifest()
	if err != nil {
		t.Fatal(err)
	}

	if got, want := m.Layers[1].MediaType, types.DockerForeignLayer; got != want {
		t.Errorf("Wrong MediaType: %s != %s", got, want)
	}
	if got, want := m.Layers[1].URLs[0], "example.com"; got != want {
		t.Errorf("Wrong URLs: %s != %s", got, want)
	}
}

func TestFilteredWrite(t *testing.T) {
	// Make a tempfile for tarball writes.
	fp, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatalf("Error creating temp file.")
	}
	t.Log(fp.Name())
	defer fp.Close()
	defer os.Remove(fp.Name())

	// Make a random image
	randImage, err := random.Image(256, 8)
	if err != nil {
		t.Fatalf("Error creating random image.")
	}
	tag, err := name.NewTag("gcr.io/foo/bar:latest", name.StrictValidation)
	if err != nil {
		t.Fatalf("Error creating test tag.")
	}

	layers, err := randImage.Layers()
	if err != nil {
		t.Fatalf("Layers() = %v", err)
	}
	rld, err := layers[0].Digest()
	if err != nil {
		t.Fatalf("Digest() = %v", err)
	}

	lf := func(l v1.Layer) (bool, error) {
		// Filter the first layer in the image.
		if ld, err := l.Digest(); err != nil {
			return false, err
		} else {
			return ld != rld, nil
		}
	}

	if err := tarball.WriteToFile(fp.Name(), tag, randImage, tarball.WithLayerFilter(lf)); err != nil {
		t.Fatalf("Unexpected error writing tarball: %v", err)
	}

	f, err := os.Open(fp.Name())
	if err != nil {
		t.Fatalf("os.Open() = %v", err)
	}
	defer f.Close()

	tarReader := tar.NewReader(f)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("scanning tarfile: %v", err)
		}

		if strings.Contains(header.Name, rld.Hex) {
			t.Errorf("Saw file %v in tarball, want %v elided.", header.Name, rld)
		}
	}
}
