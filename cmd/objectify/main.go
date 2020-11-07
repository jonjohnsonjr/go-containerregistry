package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"golang.org/x/sync/errgroup"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("please supply a directory")
	}

	dir := os.Args[1]

	w := &writer{
		dir: dir,

		// consider hydrating these from somewhere
		downloads: map[v1.Hash]*download{},
		metadata:  map[name.Reference]v1.Descriptor{},
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if err := w.process(line); err != nil {
			log.Fatal(err)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Println(err)
	}

	for ref, desc := range w.metadata {
		fmt.Printf(`%s
  -H "Content-Type: %s"
  -H "Content-Length: %d"
  -H "Docker-Content-Digest: %s"
`, ref.String(), desc.MediaType, desc.Size, desc.Digest)
	}
}

type writer struct {
	dir string

	sync.Mutex
	downloads map[v1.Hash]*download
	metadata  map[name.Reference]v1.Descriptor
}

type download struct {
	sync.RWMutex
	filename string
}

func (w *writer) process(line string) error {
	ref, err := name.ParseReference(line)
	if err != nil {
		return fmt.Errorf("failed to parse %q: %v", line, err)
	}
	desc, err := remote.Get(ref)
	if err != nil {
		return err
	}
	switch desc.MediaType {
	case types.OCIImageIndex, types.DockerManifestList:
		ii, err := desc.ImageIndex()
		if err != nil {
			return err
		}

		if err := w.writeIndex(ref, ii); err != nil {
			return err
		}
	case types.OCIManifestSchema1, types.DockerManifestSchema2:
		img, err := desc.Image()
		if err != nil {
			return err
		}
		if err := w.writeImage(ref, img); err != nil {
			return err
		}
	}

	return nil
}

// TODO: storage interface
func writeFile(target string, r io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(target), os.ModePerm); err != nil && !os.IsExist(err) {
		return err
	}

	w, err := os.OpenFile(target, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
	if os.IsExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer w.Close()

	_, err = io.Copy(w, r)
	return err
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	log.Printf("Copy %s -> %s", src, dst)
	return writeFile(dst, in)
}

func fileExists(file string) bool {
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		return true
	}
	return false
}

func (w *writer) blobExists(repo name.Repository, h v1.Hash) bool {
	target := filepath.Join(w.dir, "v2", repo.RepositoryStr(), "blobs", h.String())
	return fileExists(target)
}

func (w *writer) writeBlob(repo name.Repository, layer v1.Layer, digest v1.Hash) error {
	target := filepath.Join(w.dir, "v2", repo.RepositoryStr(), "blobs", digest.String())

	// Lock the downloads in case we need to create one.
	w.Lock()
	if d, ok := w.downloads[digest]; ok {
		// This is in progress, we don't need to update downloads.
		w.Unlock()

		// Wait for download to finish.
		d.RLock()
		defer d.RLock()

		// Copy from download.path
		return copyFile(d.filename, target)
	} else {
		// This is a new blob, create a new download and lock it until we are done.
		d := &download{
			filename: target,
		}
		d.Lock()
		defer d.Unlock()

		w.downloads[digest] = d

		// Done modifying downloads map.
		w.Unlock()

		log.Printf("Download %s/%s", repo, digest)
		r, err := layer.Compressed()
		if err != nil {
			return err
		}

		return writeFile(target, r)
	}
}

type manifest interface {
	RawManifest() ([]byte, error)
	MediaType() (types.MediaType, error)
	Digest() (v1.Hash, error)
}

func (w *writer) manifestDigestExists(ref name.Reference, h v1.Hash) bool {
	target := filepath.Join(w.dir, "v2", ref.Context().RepositoryStr(), "manifests", h.String())
	return fileExists(target)
}

func (w *writer) manifestExists(ref name.Reference, man manifest) (bool, error) {
	h, err := man.Digest()
	if err != nil {
		return false, err
	}
	return w.manifestDigestExists(ref, h), nil
}

func (w *writer) writeManifest(ref name.Reference, man manifest) error {
	b, err := man.RawManifest()
	if err != nil {
		return err
	}
	mt, err := man.MediaType()
	if err != nil {
		return err
	}
	h, sz, err := v1.SHA256(bytes.NewReader(b))
	if err != nil {
		return err
	}

	refs := []name.Reference{ref}
	if _, ok := ref.(name.Tag); ok {
		refs = append(refs, ref.Context().Digest(h.String()))
	}
	for _, ref := range refs {
		w.metadata[ref] = v1.Descriptor{
			MediaType: mt,
			Size:      sz,
			Digest:    h,
		}
		target := filepath.Join(w.dir, "v2", ref.Context().RepositoryStr(), "manifests", ref.Identifier())
		if err := writeFile(target, bytes.NewReader(b)); err != nil {
			return err
		}
	}

	return nil
}

func (w *writer) writeImage(ref name.Reference, img v1.Image) error {
	if ok, err := w.manifestExists(ref, img); ok {
		log.Printf("%s already exists", ref)
	} else {
		if err != nil {
			log.Printf("manifestExists(%s): %v", ref, err)
		}

		log.Printf("Pull %s", ref)
		ls, err := img.Layers()
		if err != nil {
			return err
		}
		cl, err := partial.ConfigLayer(img)
		if err != nil {
			return err
		}
		ls = append(ls, cl)

		var g errgroup.Group
		for _, l := range ls {
			l := l

			g.Go(func() error {
				// Handle foreign layers.
				mt, err := l.MediaType()
				if err != nil {
					return err
				}
				if !mt.IsDistributable() {
					// TODO(jonjohnsonjr): Add "allow-nondistributable-artifacts" option.
					return nil
				}

				// Streaming layers calculate their digests while uploading them. Assume
				// an error here indicates we need to upload the layer.
				h, err := l.Digest()
				if err != nil {
					return err
				}

				if w.blobExists(ref.Context(), h) {
					return nil
				}

				return w.writeBlob(ref.Context(), l, h)
			})
		}

		// Wait for the layers + config.
		if err := g.Wait(); err != nil {
			return err
		}
	}

	return w.writeManifest(ref, img)
}

func (w *writer) writeIndex(ref name.Reference, ii v1.ImageIndex) error {
	if ok, err := w.manifestExists(ref, ii); ok {
		log.Printf("%s already exists", ref)
	} else {
		if err != nil {
			log.Printf("manifestExists(%s): %v", ref, err)
		}

		log.Printf("Pull %s", ref)
		index, err := ii.IndexManifest()
		if err != nil {
			return err
		}
		for _, desc := range index.Manifests {
			ref := ref.Context().Digest(desc.Digest.String())
			if w.manifestDigestExists(ref, desc.Digest) {
				continue
			}

			switch desc.MediaType {
			case types.OCIImageIndex, types.DockerManifestList:
				ii, err := ii.ImageIndex(desc.Digest)
				if err != nil {
					return err
				}

				if err := w.writeIndex(ref, ii); err != nil {
					return err
				}
			case types.OCIManifestSchema1, types.DockerManifestSchema2:
				img, err := ii.Image(desc.Digest)
				if err != nil {
					return err
				}
				if err := w.writeImage(ref, img); err != nil {
					return err
				}
			}
		}
	}

	return w.writeManifest(ref, ii)
}
