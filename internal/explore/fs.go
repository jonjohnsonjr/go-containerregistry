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

	"github.com/google/go-containerregistry/internal/httpserve"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Lots of debugging that we don't want to compile into the binary.
const debug = false

func debugf(s string, i ...interface{}) {
	if debug {
		log.Printf(s, i...)
	}
}

// More than enough for FileServer to Peek at file contents.
const bufferLen = 2 << 16

type tarReader interface {
	io.Reader
	Next() (*tar.Header, error)
}

type withSize interface {
	Size() (int64, error)
}

// Implements http.FileSystem.
type layerFS struct {
	prefix  string
	tr      tarReader
	headers []*tar.Header

	ref  string
	size int64
	kind string
}

func (h *handler) newLayerFS(tr tarReader, size int64, prefix, ref, kind string) (*layerFS, error) {
	fs := &layerFS{
		tr:     tr,
		size:   size,
		prefix: prefix,
		ref:    ref,
	}

	fs.headers = []*tar.Header{}

	return fs, nil
}

func (fs *layerFS) reset() error {
	return nil
}

func renderHeader(w http.ResponseWriter, fname string, prefix string, ref name.Reference, kind string, size int64, f httpserve.File, ctype string) error {
	stat, err := f.Stat()
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := headerTmpl.Execute(w, TitleData{ref.String()}); err != nil {
		return err
	}

	filename := strings.TrimPrefix(fname, "/"+prefix)
	filename = strings.TrimPrefix(filename, "/")

	header, ok := stat.Sys().(*tar.Header)
	if ok {
		filename = header.Name
	} else {
		if !stat.IsDir() {
			logs.Debug.Printf("not a tar header or directory")
		}
	}

	mediaType := types.DockerUncompressedLayer
	tarflags := "tar -Ox "
	if kind == "tar+gzip" {
		tarflags = "tar -Oxz "
		mediaType = types.DockerLayer
	} else if kind == "tar+zstd" {
		tarflags = "tar --zstd -Ox "
		mediaType = types.MediaType("application/vnd.oci.image.layer.v1.tar+zstd")
	}

	hash, err := v1.NewHash(ref.Identifier())
	if err != nil {
		return err
	}

	filelink := filename

	// Compute links for JQ
	fprefix := ""
	if strings.HasPrefix(filename, "./") {
		fprefix = "./"
	}
	filename = strings.TrimSuffix(filename, "/")
	dir := path.Dir(filename)
	if dir != "." {
		base := path.Base(filename)
		sep := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(filename, fprefix), dir), base)

		href := path.Join(prefix, dir)
		htext := fprefix + dir + sep

		logs.Debug.Printf("dir=%q, sep=%q, base=%q, href=%q, htext=%q", dir, sep, base, href, htext)
		dirlink := fmt.Sprintf(`<a class="mt" href="/%s">%s</a>`, href, htext)
		filelink = dirlink + base
	}

	data := HeaderData{
		Repo:      ref.Context().String(),
		Reference: ref.String(),
		Descriptor: &v1.Descriptor{
			Size:      size,
			Digest:    hash,
			MediaType: mediaType,
		},
		Handler: handlerForMT(string(mediaType)),
		//EscapedMediaType: url.QueryEscape(string(mediaType)),
		MediaTypeLink: getLink(string(mediaType)),
		Up: &RepoParent{
			Parent:    ref.Context().String(),
			Separator: "@",
			Child:     ref.Identifier(),
		},
		JQ: crane + " blob " + ref.String() + " | " + tarflags + " " + filelink,
	}
	if ctype == "application/octet-stream" {
		truncate := int64(1 << 15)
		if stat.Size() > truncate {
			data.JQ = data.JQ + fmt.Sprintf(" | head -c %d", truncate)
		}
		data.JQ = data.JQ + " | xxd"
	}

	if stat.IsDir() {
		tarflags = "tar -tv "
		if kind == "tar+gzip" {
			tarflags = "tar -tvz "
		} else if kind == "tar+zstd" {
			tarflags = "tar --zstd -tv "
		}

		data.JQ = crane + " blob " + ref.String() + " | " + tarflags + " " + filelink
	}

	if err := bodyTmpl.Execute(w, data); err != nil {
		return err
	}
	return nil
}

func (fs *layerFS) RenderHeader(w http.ResponseWriter, fname string, f httpserve.File, ctype string) error {
	if fs.kind == "" {
		// TODO: Do something better for indices.
	}
	ref, err := name.ParseReference(fs.ref)
	if err != nil {
		return err
	}
	return renderHeader(w, fname, strings.Trim(fs.prefix, "/"), ref, fs.kind, fs.size, f, ctype)
}

// TODO: Check to see if we hit tr or rc EOF and reset.
func (fs *layerFS) Open(original string) (httpserve.File, error) {
	name := strings.TrimPrefix(original, fs.prefix)

	// This is a bit nasty. For symlinks and hardlinks, we have to handle:
	//   "source -> target"
	//
	// So we need to parse target out of that string to get the filename
	// that we actually need to open.
	chunks := strings.Split(name, " -> ")
	name = chunks[len(chunks)-1]

	debugf("Open(%q) -> Open(%q)", original, name)

	size := 0
	// Scan through the layer, looking for a matching tar.Header.Name.
	for {
		header, err := fs.tr.Next()
		if err == io.EOF {
			debugf("Open(%q): EOF", name)

			// Don't bother chasing this.
			if path.Base(name) == "index.html" {
				break
			}

			chased, err := fs.chase(name, 0)
			if err == nil {
				debugf("chase(%s) -> %s, resetting", name, chased.Name)
				name = path.Clean("/" + chased.Name)
				size = 0
				if err := fs.reset(); err != nil {
					return nil, err
				}
				continue
			}

			break
		}
		if err != nil {
			log.Printf("Open(%q): %v", name, err)
			return nil, err
		}
		// debugf("Open(%q): header.Name = %q, header.Size = %d", name, header.Name, header.Size)

		// Cache the headers, so we don't have to re-fetch the blob. This comes
		// into play mostly for ReadDir() at the top level, where we already scan
		// the entire layer to tell FileServer "/" and "index.html" don't exist.
		fs.headers = append(fs.headers, header)
		size += int(unsafe.Sizeof(*header))
		if path.Clean("/"+header.Name) == name {
			debugf("Open(%q): %s %d %s %s %s", name, typeStr(header.Typeflag), header.Size, header.ModTime, header.Name, header.Linkname)

			return &layerFile{
				name:   name,
				header: header,
				fs:     fs,
			}, nil
		}
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

func (fs *layerFS) chase(original string, gen int) (*tar.Header, error) {
	if original == "" {
		return nil, fmt.Errorf("empty string")
	}
	if gen > 64 {
		log.Printf("chase(%q) aborting at gen=%d", original, gen)
		return nil, fmt.Errorf("too many symlinks")
	}
	debugf("chase(%q)", original)
	name := path.Clean("/" + original)
	dir := path.Dir(name)
	dirs := []string{dir}
	if dir != "" && dir != "." {
		prev := dir
		// Walk up to the first directory.
		for next := prev; next != "." && filepath.ToSlash(next) != "/"; prev, next = next, filepath.Dir(next) {
			debugf("chase(%q): dir: %q, prev: %q, next: %q", name, dir, prev, next)
			dirs = append(dirs, strings.TrimPrefix(next, "/"))
		}
	}

	for _, header := range fs.headers {
		if header.Name == original {
			if header.Typeflag == tar.TypeSymlink {
				return fs.chase(header.Linkname, gen+1)
			}
			return header, nil
		}
		if header.Typeflag == tar.TypeSymlink {
			for _, dir := range dirs {
				if header.Name == dir {
					// todo: re-fetch header.Linkname/<rest>
					prefix := path.Clean("/" + header.Name)
					next := path.Join(header.Linkname, strings.TrimPrefix(name, prefix))
					return fs.chase(next, gen+1)
				}
			}
		}
	}

	return nil, fmt.Errorf("could not find: %s", original)
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
	debugf("Open(%q).Seek(%d, %d) @ [%d, %d]", f.name, offset, whence, f.cursor, f.peeked)

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

	debugf("Open(%q).Seek(%d, %d): whence: ???", f.name, offset, whence)
	return 0, fmt.Errorf("not implemented")
}

func (f *layerFile) tooBig() []byte {
	crane := fmt.Sprintf("crane blob %s | gunzip | tar -Oxf - %s", f.fs.ref, f.name)
	data := []byte("this file is too big, use crane to download it:\n\n" + crane)
	return data
}

func (f *layerFile) Read(p []byte) (int, error) {
	debugf("Read(%q): len(p) = %d", f.name, len(p))

	if f.header.Size > respTooBig {
		log.Printf("too big")
		return bytes.NewReader(f.tooBig()).Read(p)
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
			debugf("Read(%q): len(p) = %d", f.name, len(p))
			f.buf = bufio.NewReaderSize(f.fs.tr, len(p))
		}

		// Peek to handle the first content sniff.
		b, err := f.buf.Peek(len(p))
		if debug {
			log.Printf("Read(%q): Peek(%d): (%d, %v)", f.name, len(p), len(b), err)
			//log.Printf("%s", string(b))
		}

		f.peeked = f.cursor + int64(len(b))

		if err == io.EOF {
			debugf("hit EOF")
			return bytes.NewReader(b).Read(p)
		} else if err != nil {
			if f.header.Size >= int64(len(p)) {
				// This should have worked...
				log.Printf("Read(%q): f.header.Size = %d, err: %v", f.name, f.header.Size, err)
			}
			return 0, err
		}

		n, err := bytes.NewReader(b).Read(p)
		debugf("Read(%q): (Peek(%d)) = (%d, %v)", f.name, len(p), n, err)
		return n, err
	}

	// We did a Peek() but didn't get a Seek() to reset.
	if f.peeked != 0 {
		if f.peeked == f.header.Size {
			debugf("Read(%q): f.peeked=%d, f.header.size=%d", f.name, f.peeked, f.header.Size)
			// We hit EOF.
			return 0, io.EOF
		}

		debugf("Read(%q): f.peeked=%d, f.cursor=%d, f.header.size=%d, discarding rest", f.name, f.peeked, f.cursor, f.header.Size)
		// We need to throw away some peeked bytes to continue with the read.
		if _, err := f.buf.Discard(int(f.peeked - f.cursor)); err != nil {
			debugf("Read(%q): discard err: %v", f.name, err)
			return 0, err
		}
		// Reset peeked to zero so we know we don't have to discard anymore.
		f.peeked = 0
	}
	n, err := f.buf.Read(p)
	if debug {
		log.Printf("Read(%q) = (%d, %v)", f.name, n, err)
		//log.Printf("%s", string(p))
	}
	return n, err
}

func (f *layerFile) Close() error {
	debugf("Close(%q)", f.name)
	return nil
}

// Scan through the tarball looking for prefixes that match the layerFile's name.
// TODO: respect count?
func (f *layerFile) Readdir(count int) ([]os.FileInfo, error) {
	debugf("ReadDir(%q)", f.name)

	if f.header != nil && f.header.Typeflag == tar.TypeSymlink {
		fi := f.header.FileInfo()
		return []os.FileInfo{symlink{
			FileInfo: fi,
			name:     ".",
			link:     f.header.Linkname,
		}}, nil
	}

	prefix := path.Clean("/" + f.name)
	if f.Root() {
		prefix = "/"
	}
	fis := []os.FileInfo{}
	if !f.Root() {
		fis = append(fis, fileInfo{".."})
	}
	for _, hdr := range f.fs.headers {
		name := path.Clean("/" + hdr.Name)
		dir := path.Dir(strings.TrimPrefix(name, prefix))
		//debugf("hdr.Name=%q prefix=%q name=%q dir=%q", hdr.Name, prefix, name, dir)

		// Is this file in this directory?
		if strings.HasPrefix(name, prefix) && (f.Root() && dir == "." || dir == "/") {
			debugf("Readdir(%q) -> %q match!", f.name, hdr.Name)
			fi := hdr.FileInfo()
			if !isLink(hdr) {
				fis = append(fis, fi)
				continue
			}

			// The symlink struct handles magic names for making things work.
			fi = symlink{
				FileInfo: fi,
				name:     fi.Name(),
				link:     hdr.Linkname,
				typeflag: hdr.Typeflag,
			}
			fis = append(fis, fi)
		}
	}

	// If we don't find anything in here, but there were subdirectories per the tarball
	// paths, synthesize some directories.
	if len(fis) == 0 {
		debugf("ReadDir(%q): No matching headers in %d entries, synthesizing directories", f.name, len(f.fs.headers))
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
					debugf("ReadDir(%q): dir: %q, prev: %q, next: %q", f.name, dir, prev, next)
				}
				dirs[prev] = struct{}{}
			}
		}
		for dir := range dirs {
			debugf("ReadDir(%q): dir: %q", f.name, dir)
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
	debugf("Stat(%q)", f.name)
	if f.Root() {
		debugf("Stat(%q): root!", f.name)
		return fileInfo{f.name}, nil
	}
	debugf("Stat(%q): nonroot!", f.name)

	if f.header == nil {
		log.Printf("! Stat(%q): no header!", f.name)

		// This is a non-existent entry in the tarball, we need to synthesize one.
		return fileInfo{f.name}, nil
	}

	// If you try to load a symlink directly, we will render it as a directory.
	if f.header.Typeflag == tar.TypeSymlink {
		hdr := *f.header
		hdr.Typeflag = tar.TypeDir
		return hdr.FileInfo(), nil
	}

	if f.header.Size > respTooBig {
		return bigFifo{
			name:    f.header.Name,
			content: f.tooBig(),
		}, nil
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
	debugf("%q.Name()", f.name)
	return f.name
}

func (f fileInfo) Size() int64 {
	debugf("%q.Size()", f.name)
	return 0
}

func (f fileInfo) Mode() os.FileMode {
	debugf("%q.Mode()", f.name)
	return os.ModeDir
}

func (f fileInfo) ModTime() time.Time {
	debugf("%q.ModTime()", f.name)
	if f.name == "" || f.name == "/" || f.name == "/index.html" {
		return time.Now()
	}
	return time.Unix(0, 0)
}

func (f fileInfo) IsDir() bool {
	debugf("%q.IsDir()", f.name)
	return true
}

func (f fileInfo) Sys() interface{} {
	debugf("%q.Sys()", f.name)
	return nil
}

type symlink struct {
	os.FileInfo
	name     string
	link     string
	typeflag byte
}

// We want the UI to show that this is a symlink, but we also want it to work!
// This isn't just a display name, this is the actual name that we need to
// handle later when FileServer attempts to open the file.
func (s symlink) Name() string {
	return s.name
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

// Implements os.FileInfo for a file that is too large.
type bigFifo struct {
	name    string
	content []byte
}

func (b bigFifo) Name() string {
	debugf("%q.Name()", b.name)
	return b.name
}

func (b bigFifo) Size() int64 {
	debugf("%q.Size()", b.name)
	return int64(len(b.content))
}

func (b bigFifo) Mode() os.FileMode {
	debugf("%q.Mode()", b.name)
	return 0
}

func (b bigFifo) ModTime() time.Time {
	debugf("%q.ModTime()", b.name)
	return time.Now()
}

func (b bigFifo) IsDir() bool {
	debugf("%q.IsDir()", b.name)
	return false
}

func (b bigFifo) Sys() interface{} {
	debugf("%q.Sys()", b.name)
	return nil
}
