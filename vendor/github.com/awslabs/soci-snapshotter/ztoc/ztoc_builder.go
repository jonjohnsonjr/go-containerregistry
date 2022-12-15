/*
   Copyright The Soci Snapshotter Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package ztoc

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"syscall"

	"github.com/awslabs/soci-snapshotter/compression"
	"github.com/opencontainers/go-digest"
	"golang.org/x/sync/errgroup"
)

type Opener func() (io.ReadCloser, error)

func mkfifo() (string, error) {
	tmpdir, err := os.MkdirTemp("", "")
	if err != nil {
		return "", err
	}
	fname := filepath.Join(tmpdir, "ztocfifo")
	if err := syscall.Mkfifo(fname, 0666); err != nil {
		return "", err
	}

	return fname, nil
}

func openfifo(fname string) (*os.File, error) {
	return os.OpenFile(fname, os.O_WRONLY|os.O_CREATE, os.ModeNamedPipe)
}

func newFile(r io.Reader) (string, func() error, error) {
	tmpdir, err := os.MkdirTemp("", "")
	if err != nil {
		return "", nil, err
	}
	fname := filepath.Join(tmpdir, "ztocfifo")
	if err := syscall.Mkfifo(fname, 0666); err != nil {
		return "", nil, err
	}
	go func() error {
		log.Printf("go()")

		f, err := os.OpenFile(fname, os.O_WRONLY|os.O_CREATE, os.ModeNamedPipe)
		if err != nil {
			log.Printf("err: %v", err)
			return err
		}
		log.Printf("OpenFile")

		bw := bufio.NewWriterSize(f, 2<<16)
		log.Printf("Copy()")
		if _, err := io.Copy(bw, r); err != nil {
			log.Printf("err: %v", err)
			return err
		}
		log.Printf("Flush()")
		if err := bw.Flush(); err != nil {
			log.Printf("err: %v", err)
			return err
		}
		log.Printf("returning")
		if err := f.Close(); err != nil {
			log.Printf("err: %v", err)
			return err
		}
		return nil
	}()

	cleanup := func() error {
		return os.RemoveAll(tmpdir)
	}
	return fname, cleanup, nil
}

func BuildZtocFromReader(open Opener, span int64, buildToolIdentifier string, size int64) (*Ztoc, error) {
	rc, err := open()
	if err != nil {
		return nil, err
	}

	fname, err := mkfifo()
	if err != nil {
		return nil, err
	}

	var fm []FileMetadata
	var g errgroup.Group
	g.Go(func() error {
		f, err := openfifo(fname)
		if err != nil {
			return err
		}
		bw := bufio.NewWriterSize(f, 2<<16)
		tr := io.TeeReader(rc, bw)

		// The way this works causes the gzip data to be decompressed twice :/
		// I'm honestly not sure how to work around that without teaching the gzip
		// code about tar
		fm, err = getGzipFileMetadata(tr)
		if err != nil {
			return err
		}

		if err := bw.Flush(); err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		return nil
	})

	index, err := compression.NewGzipZinfoFromFile(fname, span)
	if err != nil {
		return nil, err
	}
	defer index.Close()

	usize := compression.Offset(index.UncompressedSize())
	if err := os.RemoveAll(filepath.Dir(fname)); err != nil {
		return nil, err
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	// TODO: move to C code? don't need this?
	// digests, err := GetPerSpanDigests(open, size, index)
	// if err != nil {
	// 	return nil, err
	// }

	checkpoints, err := index.Bytes()
	if err != nil {
		return nil, err
	}

	toc := TOC{
		Metadata: fm,
	}

	compressionInfo := CompressionInfo{
		MaxSpanID: index.MaxSpanID(),
		// SpanDigests: digests,
		Checkpoints: checkpoints,
	}

	return &Ztoc{
		Version:                 "0.9",
		TOC:                     toc,
		CompressedArchiveSize:   compression.Offset(size),
		UncompressedArchiveSize: usize,
		BuildToolIdentifier:     buildToolIdentifier,
		CompressionInfo:         compressionInfo,
	}, nil
}

func BuildZtoc(gzipFile string, span int64, buildToolIdentifier string) (*Ztoc, error) {
	if gzipFile == "" {
		return nil, fmt.Errorf("need to provide gzip file")
	}
	fs, err := getFileSize(gzipFile)
	if err != nil {
		return nil, err
	}
	fopen := func() (io.ReadCloser, error) { return os.Open(gzipFile) }
	return BuildZtocFromReader(fopen, span, buildToolIdentifier, int64(fs))
}

func GetPerSpanDigests(open Opener, fileSize int64, index *compression.GzipZinfo) ([]digest.Digest, error) {
	file, err := open()
	if err != nil {
		return nil, fmt.Errorf("could not open file for reading: %w", err)
	}
	defer file.Close()

	cursor := int64(0)

	var digests []digest.Digest
	var i compression.SpanID
	maxSpanID := index.MaxSpanID()
	for i = 0; i <= maxSpanID; i++ {
		var (
			startOffset = index.SpanIDToCompressedOffset(i)
			endOffset   compression.Offset
		)

		if index.HasBits(i) {
			startOffset--
		}

		if i == maxSpanID {
			endOffset = compression.Offset(fileSize)
		} else {
			endOffset = index.SpanIDToCompressedOffset(i + 1)
		}

		discard := int64(startOffset) - cursor
		size := int64(endOffset - startOffset)
		// log.Printf("discarding: %d, cursor=%d, size=%d", discard, cursor, size)
		cursor = int64(endOffset)
		if _, err := io.CopyN(ioutil.Discard, file, discard); err != nil {
			return nil, fmt.Errorf("discarding: %w", err)
		}
		// log.Printf("limited read span=%d, start=%d, end=%d, fileSize=%d, size=%d, cursor=%d", i, startOffset, endOffset, fileSize, size, cursor)
		lr := &io.LimitedReader{
			R: file,
			N: size,
		}
		// log.Printf("Section span=%d, start=%d, end=%d, size=%d", i, startOffset, endOffset, fileSize)
		// section := io.NewSectionReader(file, int64(startOffset), int64(endOffset-startOffset))
		dgst, err := digest.FromReader(lr)
		if err != nil {
			return nil, fmt.Errorf("unable to compute digest for section; start=%d, end=%d, size=%d err: %w", startOffset, endOffset, fileSize, err)
		}
		digests = append(digests, dgst)
	}
	return digests, nil
}

func getGzipFileMetadata(file io.Reader) ([]FileMetadata, error) {
	gzipRdr, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("could not create gzip reader: %v", err)
	}

	pt := &positionTrackerReader{r: gzipRdr}
	tarRdr := tar.NewReader(pt)
	var md []FileMetadata

	for {
		hdr, err := tarRdr.Next()
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return nil, fmt.Errorf("error while reading tar header: %w", err)
			}
		}

		fileType, err := getType(hdr)
		if err != nil {
			return nil, err
		}

		metadataEntry := FileMetadata{
			Name:               hdr.Name,
			Type:               fileType,
			UncompressedOffset: pt.CurrentPos(),
			UncompressedSize:   compression.Offset(hdr.Size),
			Linkname:           hdr.Linkname,
			Mode:               hdr.Mode,
			UID:                hdr.Uid,
			GID:                hdr.Gid,
			Uname:              hdr.Uname,
			Gname:              hdr.Gname,
			ModTime:            hdr.ModTime,
			Devmajor:           hdr.Devmajor,
			Devminor:           hdr.Devminor,
			Xattrs:             hdr.PAXRecords,
		}
		md = append(md, metadataEntry)
	}
	return md, nil
}

func getFileSize(file string) (compression.Offset, error) {
	f, err := os.Open(file)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return compression.Offset(st.Size()), nil
}

func getType(header *tar.Header) (fileType string, e error) {
	switch header.Typeflag {
	case tar.TypeLink:
		fileType = "hardlink"
	case tar.TypeSymlink:
		fileType = "symlink"
	case tar.TypeDir:
		fileType = "dir"
	case tar.TypeReg:
		fileType = "reg"
	case tar.TypeChar:
		fileType = "char"
	case tar.TypeBlock:
		fileType = "block"
	case tar.TypeFifo:
		fileType = "fifo"
	default:
		return "", fmt.Errorf("unsupported input tar entry %q", header.Typeflag)
	}
	return
}

type positionTrackerReader struct {
	r   io.Reader
	pos compression.Offset
}

func (p *positionTrackerReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if err == nil {
		p.pos += compression.Offset(n)
	}
	return n, err
}

func (p *positionTrackerReader) CurrentPos() compression.Offset {
	return p.pos
}
