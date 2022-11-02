// Copyright 2021 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package explore

import (
	"archive/tar"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/google/go-containerregistry/internal/and"
	"github.com/google/go-containerregistry/internal/gzip"
)

// Lots of debugging that we don't want to compile into the binary.
const debug = false

// More than enough for FileServer to Peek at file contents.
const bufferLen = 2 << 16

// Implements http.FileSystem.
type layerFS struct {
	// The HTTP request that originated this filesystem, useful for resetting.
	req *http.Request
	w   http.ResponseWriter
	h   *handler

	ref      string
	digest   string
	rc       io.ReadCloser
	tr       *tar.Reader
	headers  []*tar.Header
	complete bool
}

func (h *handler) newLayerFS(w http.ResponseWriter, r *http.Request) (*layerFS, error) {
	fs := &layerFS{
		req: r,
		w:   w,
		h:   h,
	}

	if err := fs.reset(); err != nil {
		return nil, err
	}

	return fs, nil
}

// refetches the blob in case FileServer has sent us over the edge
func (fs *layerFS) reset() error {
	log.Printf("reset %s", fs.req.URL.String())
	blob, ref, err := fs.h.fetchBlob(fs.w, fs.req)
	if err != nil {
		return err
	}

	ok, pr, err := gzip.Peek(blob)
	var rc io.ReadCloser
	rc = &and.ReadCloser{Reader: pr, CloseFunc: blob.Close}
	if err != nil {
		log.Printf("gzip.Peek(%q) = %v", ref, err)
	}
	if ok {
		rc, err = gzip.UnzipReadCloser(rc)
		if err != nil {
			return err
		}
	}

	if fs.rc != nil {
		if err := fs.rc.Close(); err != nil {
			log.Printf("layerFs(%q).rc.Close() = %v", ref, err)
		}
	}

	fs.rc = rc
	fs.tr = tar.NewReader(rc)

	fs.ref = ref

	chunks := strings.SplitN(ref, "@", 2)
	if len(chunks) != 2 {
		return fmt.Errorf("not enough chunks: %s", ref)
	}
	fs.digest = chunks[1]
	if !fs.complete {
		fs.headers = []*tar.Header{}
	}

	return nil
}

func (fs *layerFS) Close() error {
	if fs.rc == nil {
		return nil
	}
	return fs.rc.Close()
}

// TODO: Check to see if we hit tr or rc EOF and reset.
func (fs *layerFS) Open(original string) (http.File, error) {
	name := strings.TrimPrefix(original, fs.ref)

	// This is a bit nasty. For symlinks and hardlinks, we have to handle:
	//   "source -> target"
	//
	// So we need to parse target out of that string to get the filename
	// that we actually need to open.
	chunks := strings.Split(name, " -> ")
	name = chunks[len(chunks)-1]

	log.Printf("Open(%q) -> Open(%q)", original, name)

	if fs.complete {
		found := false
		if debug {
			log.Printf("headers len: %d", len(fs.headers))
		}
		// we already have headers, don't hit the tar reader
		for _, header := range fs.headers {
			if path.Clean("/"+header.Name) == name {
				log.Printf("cached Open(%q): %s %d %s %s %s", name, typeStr(header.Typeflag), header.Size, header.ModTime, header.Name, header.Linkname)
				if header.Typeflag == tar.TypeDir {
					if debug {
						log.Printf("is a dir")
					}
					return &layerFile{
						name:   name,
						header: header,
						fs:     fs,
					}, nil
				} else {
					if debug {
						log.Printf("not a dir")
					}
					found = true
				}
			}
		}

		if !found {
			// FileServer is trying to find index.html, but it doesn't exist in the image.
			// TODO: What if there _is_ an index.html in the root FS?
			if path.Base(name) == "index.html" {
				return nil, fmt.Errorf("nope: %s", name)
			}

			// We didn't find the entry in the tarball, so we're probably trying to list
			// a file or directory that does not exist.
			return &layerFile{
				name: name,
				fs:   fs,
			}, nil
		}
	}

	if fs.tr == nil {
		if err := fs.reset(); err != nil {
			return nil, err
		}
	}
	size := 0
	// Scan through the layer, looking for a matching tar.Header.Name.
	for {
		header, err := fs.tr.Next()
		if err == io.EOF {
			log.Printf("Open(%q): EOF", name)
			break
		}
		if err != nil {
			log.Printf("Open(%q): %v", name, err)
			return nil, err
		}
		if debug {
			log.Printf("Open(%q): header.Name = %q, header.Size = %d", name, header.Name, header.Size)
		}

		// Cache the headers, so we don't have to re-fetch the blob. This comes
		// into play mostly for ReadDir() at the top level, where we already scan
		// the entire layer to tell FileServer "/" and "index.html" don't exist.
		fs.headers = append(fs.headers, header)
		size += int(unsafe.Sizeof(*header))
		if path.Clean("/"+header.Name) == name {
			log.Printf("Open(%q): %s %d %s %s %s", name, typeStr(header.Typeflag), header.Size, header.ModTime, header.Name, header.Linkname)
			return &layerFile{
				name:   name,
				header: header,
				fs:     fs,
			}, nil
		}
	}

	if size != 0 && len(fs.headers) != 0 {
		// only cache full set of headers
		fs.h.cache.Put(&headerEntry{
			key:     fs.digest,
			headers: fs.headers,
			size:    size,
		})

		log.Printf("cached %s: (%d bytes)", fs.digest, size)
	}

	// FileServer is trying to find index.html, but it doesn't exist in the image.
	// TODO: What if there _is_ an index.html in the root FS?
	if path.Base(name) == "index.html" {
		return nil, fmt.Errorf("nope: %s", name)
	}

	// We didn't find the entry in the tarball, so we're probably trying to list
	// a file or directory that does not exist.
	return &layerFile{
		name: name,
		fs:   fs,
	}, nil
}

type peek struct {
	cursor int64
	remain int
}

// Implements http.File.
type layerFile struct {
	name   string
	header *tar.Header
	fs     *layerFS

	buf *bufio.Reader

	// The real cursor of the underlying file.
	cursor int64

	// The cursor FileServer thinks it has after a Peek.
	peeked int64
}

// The FileServer only really tries to Seek to reset the file to the start.
// It will read the first 512 bytes (sniffLen) to determine the filetype if it
// can't determine the filetype based on the file extension.
//
// I wish it would use Peek, for this, but it only takes an io.ReadSeeker.
//
// TODO: Handle offset better for range requests?
func (f *layerFile) Seek(offset int64, whence int) (int64, error) {
	if debug {
		log.Printf("Open(%q).Seek(%d, %d) @ [%d, %d]", f.name, offset, whence, f.cursor, f.peeked)
	}

	if whence == io.SeekEnd {
		// Likely just trying to determine filesize.
		// TODO: Handle f.seeked or something?
		return f.header.Size, nil
	}

	if whence == io.SeekStart {
		if offset == 0 {
			// We are seeking to the start of the file, usually after Seeking to the
			// end to determine the filesize.
			f.cursor = 0
			f.peeked = 0
			return 0, nil
		}

		if offset == f.cursor {
			// We are seeking to where the cursor is, do nothing.
			f.peeked = 0
			return offset, nil
		}

		if offset < f.cursor {
			// Seeking somewhere our cursor has already moved past, we can't respond.
			// TODO: Reset file somehow?
			log.Printf("Open(%q).Seek(%d, %d): offset < cursor: ???", f.name, offset, whence)
			return 0, fmt.Errorf("not implemented")
		}

		if offset > f.cursor {
			// We want to seek forward.
			if offset <= f.peeked {
				// But not past the Peek().
				n := offset - f.cursor
				if _, err := f.buf.Discard(int(n)); err != nil {
					return 0, err
				}
				f.cursor = f.cursor + n
				return f.cursor, nil
			}

			// We want to go past the Peek().
			n, err := f.buf.Discard(int(offset - f.cursor))
			if err != nil {
				return 0, err
			}
			f.cursor = f.cursor + int64(n)
			f.peeked = 0
			return f.cursor, nil
		}

		// Is this reachable?
		log.Printf("Open(%q).Seek(%d, %d): start: ???", f.name, offset, whence)
		return 0, fmt.Errorf("not implemented")
	}

	log.Printf("Open(%q).Seek(%d, %d): whence: ???", f.name, offset, whence)
	return 0, fmt.Errorf("not implemented")
}

func (f *layerFile) Read(p []byte) (int, error) {
	if debug {
		log.Printf("Read(%q): len(p) = %d", f.name, len(p))
	}

	// Handle first read.
	if f.buf == nil {
		if f.cursor != 0 {
			// This is a surprise!
			log.Printf("Read(%q): nil buf, cursor = %d", f.name, f.cursor)
			return 0, fmt.Errorf("invalid cursor position: %d", f.cursor)
		}

		if f.fs.tr == nil {
			if err := f.fs.reset(); err != nil {
				return 0, err
			}
		}

		if len(p) <= bufferLen {
			f.buf = bufio.NewReaderSize(f.fs.tr, bufferLen)
		} else {
			log.Printf("Read(%q): len(p) = %d", f.name, len(p))
			f.buf = bufio.NewReaderSize(f.fs.tr, len(p))
		}

		// Peek to handle the first content sniff.
		b, err := f.buf.Peek(len(p))
		if debug {
			log.Printf("Read(%q): Peek(%d): (%d, %v)", f.name, len(p), len(b), err)
			log.Printf("%s", string(b))
		}

		f.peeked = f.cursor + int64(len(b))

		if err == io.EOF {
			if debug {
				log.Printf("hit EOF")
			}
			return bytes.NewReader(b).Read(p)
		} else if err != nil {
			if f.header.Size >= int64(len(p)) {
				// This should have worked...
				log.Printf("Read(%q): f.header.Size = %d, err: %v", f.name, f.header.Size, err)
			}
			return 0, err
		}

		n, err := bytes.NewReader(b).Read(p)
		if debug {
			log.Printf("Read(%q): (Peek(%d)) = (%d, %v)", f.name, len(p), n, err)
		}
		return n, err
	}

	// We did a Peek() but didn't get a Seek() to reset.
	if f.peeked != 0 {
		if f.peeked == f.header.Size {
			if debug {
				log.Printf("Read(%q): f.peeked=%d, f.header.size=%d", f.name, f.peeked, f.header.Size)
			}
			// We hit EOF.
			return 0, io.EOF
		}

		if debug {
			log.Printf("Read(%q): f.peeked=%d, f.cursor=%d, f.header.size=%d, discarding rest", f.name, f.peeked, f.cursor, f.header.Size)
		}
		// We need to throw away some peeked bytes to continue with the read.
		if _, err := f.buf.Discard(int(f.peeked - f.cursor)); err != nil {
			if debug {
				log.Printf("Read(%q): discard err: %v", f.name, err)
			}
			return 0, err
		}
		// Reset peeked to zero so we know we don't have to discard anymore.
		f.peeked = 0
	}
	n, err := f.buf.Read(p)
	if debug {
		log.Printf("Read(%q) = (%d, %v)", f.name, n, err)
		log.Printf("%s", string(p))
	}
	return n, err
}

func (f *layerFile) Close() error {
	log.Printf("Close(%q)", f.name)
	return nil
}

// Scan through the tarball looking for prefixes that match the layerFile's name.
// TODO: respect count?
func (f *layerFile) Readdir(count int) ([]os.FileInfo, error) {
	log.Printf("ReadDir(%q)", f.name)
	prefix := path.Clean("/" + f.name)
	if f.Root() {
		prefix = "/"
	}
	fis := []os.FileInfo{}
	for _, hdr := range f.fs.headers {
		name := path.Clean("/" + hdr.Name)
		dir := path.Dir(strings.TrimPrefix(name, prefix))
		if debug {
			log.Printf("hdr.Name=%q prefix=%q name=%q dir=%q", hdr.Name, prefix, name, dir)
		}

		// Is this file in this directory?
		if strings.HasPrefix(name, prefix) && (f.Root() && dir == "." || dir == "/") {
			if debug {
				log.Printf("Readdir(%q) -> %q match!", f.name, hdr.Name)
			}
			fi := hdr.FileInfo()
			if !isLink(hdr) {
				fis = append(fis, fi)
				continue
			}

			// For links, we need to handle hardlinks and symlinks.
			link := hdr.Linkname
			if debug {
				log.Printf("name = %q, hdr.Linkname = %q, dir = %q", name, link, dir)
			}

			// For symlinks, assume relative paths.
			if hdr.Typeflag == tar.TypeSymlink {
				if !path.IsAbs(hdr.Linkname) {
					link = path.Clean(path.Join(path.Dir(name), link))
				}
				if debug {
					log.Printf("symlink: %v -> %v", hdr.Linkname, link)
				}
			}

			// For hardlinks, assume absolute paths. This seems to hold up.
			if hdr.Typeflag == tar.TypeLink {
				link = path.Clean("/" + link)

				if debug {
					log.Printf("hardlink: %v -> %v", hdr.Linkname, link)
				}
			}

			// The symlink struct handles magic names for making things work.
			fi = symlink{
				FileInfo: fi,
				name:     fi.Name(),
				link:     link,
			}
			fis = append(fis, fi)
		}
	}

	// If we don't find anything in here, but there were subdirectories per the tarball
	// paths, synthesize some directories.
	if len(fis) == 0 {
		log.Printf("ReadDir(%q): No matching headers in %d entries, synthesizing directories", f.name, len(f.fs.headers))
		dirs := map[string]struct{}{}
		for _, hdr := range f.fs.headers {
			name := path.Clean("/" + hdr.Name)

			if !strings.HasPrefix(name, prefix) {
				continue
			}

			dir := path.Dir(strings.TrimPrefix(name, prefix))
			if dir != "" && dir != "." {
				prev := dir
				// Walk up to the first directory.
				for next := prev; next != "." && next != prefix && filepath.ToSlash(next) != "/"; prev, next = next, filepath.Dir(next) {
					if debug {
						log.Printf("ReadDir(%q): dir: %q, prev: %q, next: %q", f.name, dir, prev, next)
					}
				}
				dirs[prev] = struct{}{}
			}
		}
		for dir := range dirs {
			if debug {
				log.Printf("ReadDir(%q): dir: %q", f.name, dir)
			}
			fis = append(fis, fileInfo{dir})
		}
	}

	return fis, nil
}

func (f *layerFile) contains(child string) bool {
	if f.Root() {
		return true
	}

	prefix := path.Clean("/" + f.name)
	child = path.Clean("/" + child)

	return strings.HasPrefix(child, prefix)
}

func isLink(hdr *tar.Header) bool {
	return hdr.Linkname != ""
}

func (f *layerFile) Stat() (os.FileInfo, error) {
	log.Printf("Stat(%q)", f.name)
	if f.Root() {
		if debug {
			log.Printf("Stat(%q): root!", f.name)
		}
		return fileInfo{f.name}, nil
	}
	if debug {
		log.Printf("Stat(%q): nonroot!", f.name)
	}

	if f.header == nil {
		// TODO: see if there's a symlink to the destination folder???
		log.Printf("Stat(%q): no header!", f.name)

		name := path.Clean("/" + f.name)
		dirs := []string{}
		dir := path.Dir(name)
		if dir != "" && dir != "." {
			prev := dir
			// Walk up to the first directory.
			for next := prev; next != "." && filepath.ToSlash(next) != "/"; prev, next = next, filepath.Dir(next) {
				if debug {
					log.Printf("ReadDir(%q): dir: %q, prev: %q, next: %q", f.name, dir, prev, next)
				}
			}
			dirs = append(dirs, strings.TrimPrefix(prev, "/"))
		}
		log.Println(dirs)

		// todo: func chase
		for _, header := range f.fs.headers {
			if header.Typeflag == tar.TypeSymlink {
				for _, dir := range dirs {
					if header.Name == dir {
						// todo: re-fetch header.Linkname/<rest>
						log.Printf(header.Linkname)
					}
				}
			}
		}

		// This is a non-existent entry in the tarball, we need to synthesize one.
		return fileInfo{f.name}, nil
	}
	return f.header.FileInfo(), nil
}

func (f *layerFile) Root() bool {
	return f.name == "" || f.name == "/" || f.name == "/index.html"
}

// Implements os.FileInfo for empty directory.
type fileInfo struct {
	name string
}

func (f fileInfo) Name() string {
	if debug {
		log.Printf("%q.Name()", f.name)
	}
	return f.name
}

func (f fileInfo) Size() int64 {
	if debug {
		log.Printf("%q.Size()", f.name)
	}
	return 0
}

func (f fileInfo) Mode() os.FileMode {
	if debug {
		log.Printf("%q.Mode()", f.name)
	}
	return os.ModeDir
}

func (f fileInfo) ModTime() time.Time {
	if debug {
		log.Printf("%q.ModTime()", f.name)
	}
	if f.name == "" || f.name == "/" || f.name == "/index.html" {
		return time.Now()
	}
	return time.Unix(0, 0)
}

func (f fileInfo) IsDir() bool {
	if debug {
		log.Printf("%q.IsDir()", f.name)
	}
	return true
}

func (f fileInfo) Sys() interface{} {
	if debug {
		log.Printf("%q.Sys()", f.name)
	}
	return nil
}

type symlink struct {
	os.FileInfo
	name string
	link string
}

// We want the UI to show that this is a symlink, but we also want it to work!
// This isn't just a display name, this is the actual name that we need to
// handle later when FileServer attempts to open the file.
func (s symlink) Name() string {
	return fmt.Sprintf("%s -> %s", s.name, s.link)
}

// Helpful for debugging in logs what kind of entry was in the tar header.
func typeStr(t byte) string {
	switch t {
	case tar.TypeReg:
		return "-"
	case tar.TypeLink:
		return "h"
	case tar.TypeSymlink:
		return "l"
	case tar.TypeDir:
		return "d"
	}

	return string(t)
}
