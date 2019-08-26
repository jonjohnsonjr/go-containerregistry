package cmd

import (
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
)

func setupStdin(t *testing.T, content []byte) *os.File {
	tmpfile, err := ioutil.TempFile("", "crane-edit-test")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tmpfile.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	tmpfile, err = os.Open(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	return tmpfile
}

func TestEditConfig(t *testing.T) {
	src := "gcr.io/crane/edit/config"
	cmd := NewCmdEditConfig()
	reg, err := registry.TLS("gcr.io")
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	http.DefaultTransport = reg.Client().Transport

	img, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := crane.Push(img, src); err != nil {
		log.Fatal(err)
	}

	cmd.SetArgs([]string{src})
	tmpfile := setupStdin(t, []byte("{}"))
	defer os.Remove(tmpfile.Name()) // clean up
	os.Stdin = tmpfile

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestEditManifest(t *testing.T) {
	src := "gcr.io/crane/edit/manifest"
	cmd := NewCmdEditManifest()
	reg, err := registry.TLS("gcr.io")
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	http.DefaultTransport = reg.Client().Transport

	img, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := crane.Push(img, src); err != nil {
		log.Fatal(err)
	}

	cmd.SetArgs([]string{src})
	tmpfile := setupStdin(t, []byte("{}"))
	defer os.Remove(tmpfile.Name()) // clean up
	os.Stdin = tmpfile
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestEditFilesystem(t *testing.T) {
	src := "gcr.io/crane/edit/config"
	cmd := NewCmdEditFs()
	reg, err := registry.TLS("gcr.io")
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	http.DefaultTransport = reg.Client().Transport

	img, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := crane.Push(img, src); err != nil {
		log.Fatal(err)
	}

	cmd.SetArgs([]string{src})
	cmd.Flags().Set("filename", "/foo/bar")
	tmpfile := setupStdin(t, []byte("baz"))
	defer os.Remove(tmpfile.Name()) // clean up
	os.Stdin = tmpfile
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestFindFile(t *testing.T) {
	img, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	r, h, err := findFile(img, "/does-not-exist")
	if err != nil {
		t.Fatal(err)
	}

	b, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 0 {
		t.Errorf("expected empty reader, got: %s", string(b))
	}

	if h.Name != "/does-not-exist" {
		t.Errorf("tar.Header has wrong name: %v", h)
	}
}
