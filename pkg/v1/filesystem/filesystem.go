package filesystem

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

const (
	whiteoutPrefix = ".wh."
	debug          = true
)

type FileSystem interface {
	Open(name string) (http.File, error)
}

func FromImage(img v1.Image) (FileSystem, error) {
	// TODO: Need to handle whiteout files and try each layer top -> down.
	return nil, fmt.Errorf("todo")
}

func FromLayer(l v1.Layer) (FileSystem, error) {
	lr, err := l.Uncompressed()
	if err != nil {
		return nil, err
	}
	return FromTarball(tar.NewReader(lr)), nil
}

type tarfs struct {
	files      map[string]*tarfile
	tombstones map[string]struct{}
	tr         *tar.Reader
}

func FromTarball(tr *tar.Reader) *tarfs {
	return &tarfs{
		files:      make(map[string]*tarfile),
		tombstones: make(map[string]struct{}),
		tr:         tr,
	}
}

func (fs *tarfs) Open(name string) (http.File, error) {
	name = filepath.Clean(filepath.Join("/", name))
	if debug {
		log.Printf("Open(%s)", name)
	}
	if f, ok := fs.files[name]; ok {
		return f, nil
	}

	for {
		header, err := fs.tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar: %v", err)
		}

		header.Name = filepath.Clean(filepath.Join("/", header.Name))

		base := filepath.Base(header.Name)
		dir := filepath.Dir(header.Name)
		tombstone := strings.HasPrefix(base, whiteoutPrefix)
		if tombstone {
			base = base[len(whiteoutPrefix):]
			filename := filepath.Join(dir, base)
			fs.tombstones[filename] = struct{}{}
		}

		file := &tarfile{
			header: header,
			name:   header.Name,
		}
		if header.FileInfo().IsDir() {
			if d, ok := fs.files[header.Name]; ok {
				if debug {
					log.Printf("adopting children for: %s", header.Name)
				}
				file.children = d.children
			}
		}
		fs.files[header.Name] = file

		if header.Size > 0 {
			b, err := ioutil.ReadAll(fs.tr)
			if err != nil {
				return nil, err
			}
			file.Reader = bytes.NewReader(b)
		}

		stat, err := file.Stat()
		if err != nil {
			return nil, err
		}

		if d, ok := fs.files[dir]; ok {
			if debug {
				log.Printf("found dir: %s", dir)
			}
			d.children = append(d.children, stat)
		} else {
			if debug {
				log.Printf("new dir: %s, with child: %s", dir, header.Name)
			}
			fs.files[dir] = &tarfile{
				name: dir,
				header: &tar.Header{
					Typeflag: tar.TypeDir,
				},
				children: []os.FileInfo{stat},
			}
		}

		if header.Name == name {
			return file, nil
		}
	}

	return nil, os.ErrNotExist
}

type tarfile struct {
	*bytes.Reader
	header   *tar.Header
	name     string
	children []os.FileInfo
	cursor   int
}

func (f *tarfile) Readdir(count int) ([]os.FileInfo, error) {
	if debug {
		log.Printf("%q.Readdir(%d)", f.name, count)
		for i, c := range f.children {
			log.Printf("child[%d] = %s", i, c.Name())
		}
	}
	if count <= 0 {
		return f.children, nil
	}

	if f.cursor >= len(f.children) {
		f.cursor = 0
		return nil, io.EOF
	}

	start := f.cursor
	end := start + count
	if end > len(f.children) {
		count = len(f.children) - start
		end = start + count
	}
	page := f.children[start:end]
	f.cursor += count
	return page, nil
}

func (f *tarfile) Stat() (os.FileInfo, error) {
	return f.header.FileInfo(), nil
}

func (f *tarfile) Close() error {
	return nil
}
