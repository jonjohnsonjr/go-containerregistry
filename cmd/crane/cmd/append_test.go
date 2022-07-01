// Copyright 2022 Google LLC All Rights Reserved.
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

package cmd

import (
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/types"
	specsv1 "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestAppend(t *testing.T) {
	dir := t.TempDir()
	src := "reg.example.com/crane/append:test"
	dst := filepath.Join(dir, "out")
	reg, err := registry.TLS("reg.example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	opt := []crane.Option{crane.WithTransport(reg.Client().Transport)}

	l, err := random.Layer(123, types.DockerLayer)
	if err != nil {
		t.Fatal(err)
	}

	tmpfile, err := ioutil.TempFile("", "layer")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	rc, err := l.Compressed()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := io.Copy(tmpfile, rc); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	cmd := NewCmdAppend(&opt)
	cmd.SetArgs([]string{
		"-f=" + tmpfile.Name(),
		"-t=" + src,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	digest, err := crane.Digest(src, opt...)
	if err != nil {
		t.Fatal(err)
	}

	cmd = NewCmdAppend(&opt)
	cmd.SetArgs([]string{
		"-f=" + tmpfile.Name(),
		"-t=" + src,
		"-b=" + src,
		"--set-base-image-annotations",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	img, err := crane.Pull(src, opt...)
	if err != nil {
		t.Fatal(err)
	}
	m, err := img.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := m.Annotations[specsv1.AnnotationBaseImageDigest]; ok {
		if v != digest {
			t.Errorf("got %q want %q", v, digest)
		}
	} else {
		t.Errorf("missing annotation %q", specsv1.AnnotationBaseImageDigest)
	}
	if v, ok := m.Annotations[specsv1.AnnotationBaseImageName]; ok {
		if v != src {
			t.Errorf("got %q want %q", v, src)
		}
	} else {
		t.Errorf("missing annotation %q", specsv1.AnnotationBaseImageName)
	}

	cmd = NewCmdAppend(&opt)
	cmd.SetArgs([]string{
		"-f=" + tmpfile.Name(),
		"-t=" + src,
		"-o=" + dst,
		"-b=" + src,
		"--set-base-image-annotations",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	img, err = crane.Load(dst, opt...)
	if err != nil {
		t.Fatal(err)
	}
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	if len(layers) != 3 {
		t.Errorf("expected to have two layers, got %d", len(layers))
	}
}
