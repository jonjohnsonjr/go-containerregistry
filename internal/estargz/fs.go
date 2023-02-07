package estargz

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/crfs/stargz"
	"github.com/google/go-containerregistry/pkg/logs"
)

// More than enough for FileServer to Peek at file contents.
const bufferLen = 2 << 16

func FS(sr *io.SectionReader, prefix, ref string, maxSize int64) (*StargzFS, error) {
	r, err := stargz.Open(sr)
	if err != nil {
		return nil, err
	}

	return &StargzFS{
		sr:      r,
		prefix:  prefix,
		ref:     ref,
		maxSize: maxSize,
	}, nil
}

type StargzFS struct {
	sr *stargz.Reader

	prefix  string
	ref     string
	maxSize int64
}

func (s *StargzFS) find(name string) (*stargz.TOCEntry, error) {
	logs.Debug.Printf("stargz.find(%q)", name)
	if fm, ok := s.sr.Lookup(name); ok {
		return fm, nil
	}
	return nil, fs.ErrNotExist
}

func (s *StargzFS) chase(original string, gen int) (*stargz.TOCEntry, string, error) {
	if original == "" {
		return nil, "", fmt.Errorf("empty string")
	}
	if gen > 64 {
		log.Printf("chase(%q) aborting at gen=%d", original, gen)
		return nil, "", fmt.Errorf("too many symlinks")
	}

	name := path.Clean("/" + original)
	dir := path.Dir(name)
	dirs := []string{dir}
	if dir != "" && dir != "." {
		prev := dir
		// Walk up to the first directory.
		for next := prev; next != "." && filepath.ToSlash(next) != "/"; prev, next = next, filepath.Dir(next) {
			dirs = append(dirs, strings.TrimPrefix(next, "/"))
		}
	}

	if fm, ok := s.sr.Lookup(original); ok {
		if fm.Type == "symlink" {
			return s.chase(fm.LinkName, gen+1)
		}
		return fm, "", nil
	} else if fm, ok := s.sr.Lookup(name); ok {
		if fm.Type == "symlink" {
			return s.chase(fm.LinkName, gen+1)
		}
		return fm, "", nil
	}

	// Need to expose TOC.
	// if fm.Type == "symlink" {
	// 	for _, dir := range dirs {
	// 		if fm.Name == dir {
	// 			// todo: re-fetch header.Linkname/<rest>
	// 			prefix := path.Clean("/" + fm.Name)
	// 			next := path.Join(fm.Linkname, strings.TrimPrefix(name, prefix))
	// 			return s.chase(next, gen+1)
	// 		}
	// 	}
	// }

	return nil, original, fs.ErrNotExist
}

func (s *StargzFS) ReadDir(original string) ([]fs.DirEntry, error) {
	logs.Debug.Printf("stargz.ReadDir(%q)", original)
	dir := strings.TrimPrefix(original, s.prefix)
	if dir != original {
		logs.Debug.Printf("stargz.ReadDir(%q)", dir)
	}

	// Implicit directories.
	dirs := map[string]struct{}{}

	prefix := path.Clean("/" + dir)
	de := []fs.DirEntry{}
	for _, fm := range s.files {
		fm := fm
		name := path.Clean("/" + fm.Name)

		if prefix != "/" && name != prefix && !strings.HasPrefix(name, prefix+"/") {
			continue
		}

		fdir := path.Dir(strings.TrimPrefix(name, prefix))
		if !(fdir == "/" || (fdir == "." && prefix == "/")) {
			if fdir != "" && fdir != "." {
				if fdir[0] == '/' {
					fdir = fdir[1:]
				}
				implicit := strings.Split(fdir, "/")[0]
				if implicit != "" {
					dirs[implicit] = struct{}{}
				}
			}
			continue
		}

		// Only do implicit dirs
		// TODO: Undo this to keep permissions?
		if fm.Typeflag == tar.TypeDir {
			dirname := s.dirEntry(dir, &fm).Name()
			dirs[dirname] = struct{}{}
			continue
		}

		if !isLink(&fm) {
			de = append(de, s.dirEntry(dir, &fm))
			continue
		}

		// For links, we need to handle hardlinks and symlinks.
		link := fm.Linkname

		// For symlinks, assume relative paths.
		if fm.Typeflag == tar.TypeSymlink {
			if !path.IsAbs(fm.Linkname) {
				link = path.Clean(path.Join(path.Dir(name), link))
			}
		}

		// For hardlinks, assume absolute paths. This seems to hold up.
		if fm.Typeflag == tar.TypeLink {
			link = path.Clean("/" + link)
		}

		// The linkEntry struct handles magic names for making things work.
		le := linkEntry{s, &fm, dir, link}
		de = append(de, &le)
	}

	for dir := range dirs {
		logs.Debug.Printf("Adding implicit dir: %s", dir)
		de = append(de, s.dirEntry(dir, nil))
	}

	logs.Debug.Printf("len(ReadDir(%q)) = %d", dir, len(de))
	return de, nil
}

func (s *StargzFS) extractFile(ctx context.Context, tf *stargz.TOCEntry) (io.ReadCloser, error) {
	sr, err := s.sr.OpenFile(tf.Name)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(sr), nil
}

func (s *StargzFS) err(name string) fs.File {
	return &stargzFile{
		fs:   s,
		name: name,
	}
}

func (s *StargzFS) dir(fm *stargz.TOCEntry) fs.File {
	return &stargzFile{
		fs:   s,
		name: fm.Name,
		fm:   fm,
	}
}

func (s *StargzFS) tooBig(fm *stargz.TOCEntry) fs.File {
	crane := fmt.Sprintf("crane blob %s | gunzip | tar -Oxf - %s", s.ref, fm.Name)
	data := []byte("this file is too big, use crane to download it:\n\n" + crane)
	fm.Size = int64(len(data))

	return &stargzFile{
		fs:   s,
		name: fm.Name,
		fm:   fm,
		buf:  bufio.NewReader(bytes.NewReader(data)),
	}
}

func (s *StargzFS) Open(original string) (fs.File, error) {
	logs.Debug.Printf("stargz.Open(%q)", original)
	name := strings.TrimPrefix(original, s.prefix)

	chunks := strings.Split(name, " -> ")
	name = chunks[len(chunks)-1]
	name = strings.TrimPrefix(name, "/")
	logs.Debug.Printf("stargz.Opening(%q)", name)

	fm, err := s.find(name)
	if err != nil {
		logs.Debug.Printf("stargz.Open(%q) = %v", name, err)

		base := path.Base(name)
		if base == "index.html" || base == "favicon.ico" {
			return nil, fs.ErrNotExist
		}

		chased, _, err := s.chase(name, 0)
		if err != nil {
			// Possibly a directory?
			return s.err(name), nil
		}

		if chased.Type == "dir" {
			return s.dir(chased), nil
		}

		name = path.Clean("/" + chased.Name)
		fm = chased
	}

	if int64(fm.Size) > s.maxSize {
		logs.Debug.Printf("stargz.Open(%q): too big: %d", name, fm.Size)
		return s.tooBig(fm), nil
	}

	return &stargzFile{fs: s, name: name, fm: fm}, nil
}

type stargzFile struct {
	fs     *StargzFS
	name   string
	fm     *stargz.TOCEntry
	buf    *bufio.Reader
	closer func() error

	// TODO: Figure out how to get rid of this nonsense.
	// The real cursor of the underlying file.
	cursor int64

	// The cursor FileServer thinks it has after a Peek.
	peeked int64
}

func (s *stargzFile) Stat() (fs.FileInfo, error) {
	if s.fm != nil {
		return s.fm.Stat(), nil
	}

	// We don't have an entry, so we need to synthesize one.
	return &dirInfo{s.name}, nil
}

func (s *stargzFile) Read(p []byte) (int, error) {
	logs.Debug.Printf("stargz.Read(%q): len(p) = %d", s.name, len(p))
	if s.buf == nil {
		logs.Debug.Printf("buf is nil")
		if s.cursor != 0 {
			return 0, fmt.Errorf("invalid cursor position: %d", s.cursor)
		}

		rc, err := s.fs.extractFile(context.Background(), s.fm)
		if err != nil {
			logs.Debug.Printf("extractFile: %v", err)
			return 0, err
		}
		s.closer = rc.Close

		if len(p) <= bufferLen {
			s.buf = bufio.NewReaderSize(rc, bufferLen)
		} else {
			s.buf = bufio.NewReaderSize(rc, len(p))
		}

		b, err := s.buf.Peek(len(p))
		s.peeked = s.cursor + int64(len(b))
		if err == io.EOF {
			return bytes.NewReader(b).Read(p)
		} else if err != nil {
			return 0, err
		}
		return bytes.NewReader(b).Read(p)
	}
	logs.Debug.Printf("stargz.Read(%q): f.peeked=%d, f.header.size=%d", s.name, s.peeked, s.fm.Size)
	if s.peeked != 0 {
		if s.peeked == s.fm.Size {
			return 0, io.EOF
		}
		newCursor := s.peeked
		if _, err := s.buf.Discard(int(s.peeked - s.cursor)); err != nil {
			return 0, err
		}
		s.peeked = 0
		s.cursor = newCursor
	} else if s.cursor == 0 {
		// Peek for the first read so that we can do tooBig.
		if len(p) < bufferLen {
			b, err := s.buf.Peek(len(p))
			s.peeked = s.cursor + int64(len(b))
			if err == io.EOF {
				return bytes.NewReader(b).Read(p)
			} else if err != nil {
				return 0, err
			}
			return bytes.NewReader(b).Read(p)
		}
	}
	return s.buf.Read(p)
}

func (s *stargzFile) Seek(offset int64, whence int) (int64, error) {
	logs.Debug.Printf("stargz.Open(%q).Seek(%d, %d) @ [%d, %d]", s.name, offset, whence, s.cursor, s.peeked)
	if whence == io.SeekEnd {
		// Likely just trying to determine filesize.
		return s.fm.Size, nil
	}
	if whence == io.SeekStart {
		if offset == 0 {
			s.cursor = 0
			s.peeked = 0
			return 0, nil
		}
		if offset == s.cursor {
			// We are seeking to where the cursor is, do nothing.
			s.peeked = 0
			return offset, nil
		}
		if offset < s.cursor {
			// Seeking somewhere our cursor has already moved past, we can't respond.
			// TODO: Reset file somehow?
			return 0, fmt.Errorf("Open(%q).Seek(%d, %d) [offset < cursor] not implemented", s.name, offset, whence)
		}
		if offset > s.cursor {
			// We want to seek forward.
			if offset <= s.peeked {
				// But not past the Peek().
				n := offset - s.cursor
				if _, err := s.buf.Discard(int(n)); err != nil {
					return 0, err
				}
				s.cursor = s.cursor + n
				return s.cursor, nil
			}

			// We want to go past the Peek().
			n, err := s.buf.Discard(int(offset - s.cursor))
			if err != nil {
				return 0, err
			}
			s.cursor = s.cursor + int64(n)
			s.peeked = 0
			return s.cursor, nil
		}
	}
	return 0, fmt.Errorf("Open(%q).Seek(%d, %d): not implemented", s.name, offset, whence)
}

func (s *stargzFile) ReadDir(n int) ([]fs.DirEntry, error) {
	return s.fs.ReadDir(s.name)
}

func (s *stargzFile) Close() error {
	if s.closer != nil {
		return s.closer()
	}
	return nil
}

// If we don't have a file, make up a dir.
type dirInfo struct {
	name string
}

func (f dirInfo) Name() string {
	return f.name
}

func (f dirInfo) Size() int64 {
	return 0
}

func (f dirInfo) Mode() os.FileMode {
	return os.ModeDir
}

func (f dirInfo) ModTime() time.Time {
	if f.name == "" || f.name == "/" || f.name == "/index.html" {
		return time.Now()
	}
	return time.Unix(0, 0)
}

func (f dirInfo) IsDir() bool {
	return true
}

func (f dirInfo) Sys() interface{} {
	return nil
}
