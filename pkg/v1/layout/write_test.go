package layout

import (
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"io/ioutil"
	"os"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/google/go-containerregistry/pkg/v1/validate"
)

func TestWrite(t *testing.T) {
	tmp, err := ioutil.TempDir("", "write-index-test")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(tmp)

	lp, err := Read(testPath)
	if err != nil {
		t.Fatal(err)
	}
	original, err := lp.ImageIndex()
	if err != nil {
		t.Fatalf("accessing index: %v", err)
	}


	if layoutPath, err := Write(tmp, original); err != nil {
		t.Fatalf("Write(%s) = %v", tmp, err)
	} else if tmp != layoutPath.path() {
		t.Fatalf("unexpected file system path %v", layoutPath)
	}

	newLayout, err := Read(tmp)
	if err != nil {
		t.Fatal(err)
	}
	written, err := newLayout.ImageIndex()
	if err != nil {
		t.Fatalf("accessing index: %v", err)
	}

	if err := validate.Index(written); err != nil {
		t.Fatalf("validate.Read() = %v", err)
	}
}

func TestWriteErrors(t *testing.T) {
	lp, err := Read(testPath)
	if err != nil {
		t.Fatalf("Read() = %v", err)
	}
	idx, err := lp.ImageIndex()
	if err != nil {
		t.Fatalf("accessing index: %v", err)
	}

	// Found this here:
	// https://github.com/golang/go/issues/24195
	invalidPath := "double-null-padded-string\x00\x00"
	if _, err := Write(invalidPath, idx); err == nil {
		t.Fatalf("Write(%s) = nil, expected err", invalidPath)
	}
}

func TestAppendDescriptorInitializesIndex(t *testing.T) {
	tmp, err := ioutil.TempDir("", "write-index-test")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(tmp)
	temp, err := Write(tmp, empty.Index)
	if err != nil {
		t.Fatal(err)
	}

	// Append a descriptor to a non-existent layout.
	desc := v1.Descriptor{
		Digest:    bogusDigest,
		Size:      1337,
		MediaType: types.MediaType("not real"),
	}
	if err := temp.AppendDescriptor(desc); err != nil {
		t.Fatalf("AppendDescriptor(%s) = %v", tmp, err)
	}

	// Read that layout from disk and make sure the descriptor is there.
	lp, err := Read(tmp)
	if err != nil {
		t.Fatalf("Read() = %v", err)
	}
	idx, err := lp.ImageIndex()
	if err != nil {
		t.Fatalf("accessing index: %v", err)
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		t.Fatalf("IndexManifest() = %v", err)
	}
	if diff := cmp.Diff(manifest.Manifests[0], desc); diff != "" {
		t.Fatalf("bad descriptor: (-got +want) %s", diff)
	}
}

func TestAppendArtifacts(t *testing.T) {
	tmp, err := ioutil.TempDir("", "write-index-test")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(tmp)

	lp, err := Read(testPath)
	if err != nil {
		t.Fatal(err)
	}
	original, err := lp.ImageIndex()
	if err != nil {
		t.Fatalf("accessing index: %v", err)
	}

	originalManifest, err := original.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}

	// Let's reconstruct the original.
	temp, err := Write(tmp, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	for i, desc := range originalManifest.Manifests {
		// Each descriptor is annotated with its position.
		annotations := map[string]string{
			"org.opencontainers.image.ref.name": strconv.Itoa(i + 1),
		}
		switch desc.MediaType {
		case types.OCIImageIndex, types.DockerManifestList:
			ii, err := original.ImageIndex(desc.Digest)
			if err != nil {
				t.Fatal(err)
			}
			if err := temp.AppendIndex(ii, WithAnnotations(annotations)); err != nil {
				t.Fatal(err)
			}
		case types.OCIManifestSchema1, types.DockerManifestSchema2:
			img, err := original.Image(desc.Digest)
			if err != nil {
				t.Fatal(err)
			}
			if err := temp.AppendImage(img, WithAnnotations(annotations)); err != nil {
				t.Fatal(err)
			}
		}
	}

	newLayout, err := Read(tmp)
	if err != nil {
		t.Fatalf("Read() = %v", err)
	}
	reconstructed, err := newLayout.ImageIndex()
	if err != nil {
		t.Fatalf("accessing index: %v", err)
	}
	reconstructedManifest, err := reconstructed.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(originalManifest, reconstructedManifest); diff != "" {
		t.Fatalf("bad manifest: (-got +want) %s", diff)
	}
}

func TestOptions(t *testing.T) {
	tmp, err := ioutil.TempDir("", "write-index-test")
	if err != nil {
		t.Fatal(err)
	}
	temp, err := Write(tmp, empty.Index)
	annotations := map[string]string{
		"foo": "bar",
	}
	urls := []string{"https://example.com"}
	platform := v1.Platform{
		Architecture: "mill",
		OS:           "haiku",
	}
	img, err := random.Image(5, 5)
	if err != nil {
		t.Fatal(err)
	}
	options := []LayoutOption{
		WithAnnotations(annotations),
		WithURLs(urls),
		WithPlatform(platform),
	}
	err = temp.AppendImage(img, options...)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := temp.ImageIndex()
	if err != nil {
		t.Fatal(err)
	}
	indexManifest, err := idx.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}

	desc := indexManifest.Manifests[0]
	if got, want := desc.Annotations["foo"], "bar"; got != want {
		t.Fatalf("wrong annotation; got: %v, want: %v", got, want)
	}
	if got, want := desc.URLs[0], "https://example.com"; got != want {
		t.Fatalf("wrong urls; got: %v, want: %v", got, want)
	}
	if got, want := desc.Platform.Architecture, "mill"; got != want {
		t.Fatalf("wrong Architecture; got: %v, want: %v", got, want)
	}
	if got, want := desc.Platform.OS, "haiku"; got != want {
		t.Fatalf("wrong OS; got: %v, want: %v", got, want)
	}
}
