package fs

import (
	"archive/tar"
	"errors"
	"io"
	"io/fs"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func Layer(l v1.Layer) fs.FS {
	return &layerFS{l, nil}
}

func Image(img v1.Image) fs.FS {
	return &imageFS{img}
}

type layerFS struct {
	l  v1.Layer
	tr *tar.Reader
}

func (l *layerFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{
			Err: fs.ErrInvalid,
		}
	}

	// TODO: Handle resumption.
	// TODO: Handle cheap stat.

	rc, err := l.l.Uncompressed()
	if err != nil {
		return nil, err
	}
	l.tr = tar.NewReader(rc)
	for {
		header, err := l.tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, fs.ErrNotExist
		} else if err != nil {
			return nil, err
		}

		if header.Name == name {
			return &layerFile{
				header: header,
				fs:     l,
			}, nil
		}
	}
}

type layerFile struct {
	fs     *layerFS
	header *tar.Header
}

func (lf *layerFile) Stat() (fs.FileInfo, error) {
	return lf.header.FileInfo(), nil
}

func (lf *layerFile) Read(p []byte) (int, error) {
	return lf.fs.tr.Read(p)
}

func (lf *layerFile) Close() error {
	return nil
}

type imageFS struct {
	img v1.Image
}

func (i *imageFS) Open(name string) (fs.File, error) {
	return nil, nil
}
