package soci

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"

	"github.com/awslabs/soci-snapshotter/ztoc"
	"github.com/google/go-containerregistry/pkg/logs"
)

func FS(toc *ztoc.Ztoc, ra io.ReaderAt) fs.FS {
	dirs := map[string]struct{}{}
	for _, fm := range toc.TOC.Metadata {
		clean := path.Clean("/" + fm.Name)
		dir := path.Dir(clean)
		dirs[dir] = struct{}{}

		// if dir != "" && dir != "." {
		// 	prev := dir
		// 	// Walk up to the first directory.
		// 	for next := prev; next != "." && next != prefix && filepath.ToSlash(next) != "/"; prev, next = next, filepath.Dir(next) {
		// 		debugf("ReadDir(%q): dir: %q, prev: %q, next: %q", f.name, dir, prev, next)
		// 	}
		// 	dirs[prev] = struct{}{}
		// }
	}
	logs.Debug.Printf("len(dirs) = %d", len(dirs))

	return &sociFS{
		toc:  toc,
		ra:   ra,
		dirs: dirs,
	}
}

type sociFS struct {
	toc  *ztoc.Ztoc
	ra   io.ReaderAt
	dirs map[string]struct{}
}

func (s *sociFS) Open(name string) (fs.File, error) {
	logs.Debug.Printf("Open(%q)", name)

	chunks := strings.Split(name, " -> ")
	name = chunks[len(chunks)-1]

	fm, err := s.find(name)
	if err != nil {
		logs.Debug.Printf("Open(%q) = %v", name, err)

		base := path.Base(name)
		if base == "index.html" || base == "favicon.ico" {
			return nil, fmt.Errorf("nope: %s", name)
		}

		clean := path.Clean("/" + name)
		dir := path.Dir(clean)

		if _, ok := s.dirs[dir]; ok {
			logs.Debug.Printf("Open(%q) dir=%q", name, dir)
			return &sociFile{s, name, nil, nil}, nil
		}
		return nil, err
	}

	extractConfig := ztoc.FileExtractConfig{
		UncompressedSize:      fm.UncompressedSize,
		UncompressedOffset:    fm.UncompressedOffset,
		Checkpoints:           s.toc.CompressionInfo.Checkpoints,
		CompressedArchiveSize: s.toc.CompressedArchiveSize,
		MaxSpanID:             s.toc.CompressionInfo.MaxSpanID,
	}

	data, err := ztoc.ExtractFile(io.NewSectionReader(s.ra, 0, int64(s.toc.CompressedArchiveSize)), &extractConfig)
	if err != nil {
		return nil, err
	}
	logs.Debug.Printf("len(Open(%q)) = %d", name, len(data))
	return &sociFile{s, name, fm, bytes.NewReader(data)}, nil
}

func (s *sociFS) ReadDir(dir string) ([]fs.DirEntry, error) {
	logs.Debug.Printf("ReadDir(%q)", dir)
	prefix := path.Clean("/" + dir)
	de := []fs.DirEntry{}
	for _, fm := range s.toc.TOC.Metadata {
		fm := fm
		name := path.Clean("/" + fm.Name)
		fdir := path.Dir(strings.TrimPrefix(name, prefix))

		if !strings.HasPrefix(name, prefix) {
			continue
		}

		if !(fdir == "/" || (fdir == "." && prefix == "/")) {
			continue
		}

		if !isLink(&fm) {
			logs.Debug.Printf("add %q", name)
			de = append(de, s.dirEntry(dir, &fm))
			continue
		}

		// For links, we need to handle hardlinks and symlinks.
		link := fm.Linkname

		// For symlinks, assume relative paths.
		if fm.Type == "symlink" {
			if !path.IsAbs(fm.Linkname) {
				link = path.Clean(path.Join(path.Dir(name), link))
			}
		}

		// For hardlinks, assume absolute paths. This seems to hold up.
		if TarType(fm.Type) == tar.TypeLink {
			link = path.Clean("/" + link)
		}

		// The linkEntry struct handles magic names for making things work.
		le := linkEntry{s, &fm, dir, link}
		de = append(de, &le)
	}
	logs.Debug.Printf("len(ReadDir(%q)) = %d", dir, len(de))
	return de, nil
}

// Maybe put this back?
// func (s *sociFS) Stat(name string) (fs.FileInfo, error) {
// 	logs.Debug.Printf("Stat(%q)", name)
// 	fm, err := s.find(name)
// 	if err != nil {
// 		logs.Debug.Printf("Stat(%q) = %v", name, err)
// 		return nil, err
// 	}
// 	stat := TarHeader(fm).FileInfo()
// 	logs.Debug.Printf("Stat(%q) = %v", name, stat)
// 	return stat, nil
// }

func (s *sociFS) find(name string) (*ztoc.FileMetadata, error) {
	logs.Debug.Printf("find(%q)", name)
	for _, fm := range s.toc.TOC.Metadata {
		//logs.Debug.Printf("%s", path.Clean("/"+fm.Name))
		if path.Clean("/"+fm.Name) == name {
			logs.Debug.Printf("returning %q", fm.Name)
			return &fm, nil
		}
	}

	// TODO: Better error
	return nil, io.EOF
}

func (s *sociFS) dirEntry(dir string, fm *ztoc.FileMetadata) *sociDirEntry {
	return &sociDirEntry{s, dir, fm}
}

type sociFile struct {
	fs   *sociFS
	name string
	fm   *ztoc.FileMetadata
	r    *bytes.Reader
}

func (s *sociFile) Stat() (fs.FileInfo, error) {
	if s.fm != nil {
		return TarHeader(s.fm).FileInfo(), nil
	}

	// We don't have an entry, so we need to synthesize one.
	return &dirInfo{s.name}, nil
}

func (s *sociFile) Read(p []byte) (int, error) {
	return s.r.Read(p)
}

func (s *sociFile) Seek(offset int64, whence int) (int64, error) {
	return s.r.Seek(offset, whence)
}

func (s *sociFile) ReadDir(n int) ([]fs.DirEntry, error) {
	return s.fs.ReadDir(s.name)
}

func (s *sociFile) Close() error {
	return nil
}

type sociDirEntry struct {
	fs  *sociFS
	dir string
	fm  *ztoc.FileMetadata
}

func (s *sociDirEntry) Name() string {
	trimmed := strings.TrimPrefix(s.fm.Name, s.dir+"/")
	return path.Clean(trimmed)
}

func (s *sociDirEntry) IsDir() bool {
	return s.fm.Type == "dir"
}

func (s *sociDirEntry) Type() fs.FileMode {
	return TarHeader(s.fm).FileInfo().Mode()
}

func (s *sociDirEntry) Info() (fs.FileInfo, error) {
	return TarHeader(s.fm).FileInfo(), nil
}

type linkEntry struct {
	fs   *sociFS
	fm   *ztoc.FileMetadata
	dir  string
	link string
}

func (s *linkEntry) Name() string {
	trimmed := strings.TrimPrefix(s.fm.Name, s.dir+"/")
	name := path.Clean(trimmed)
	return fmt.Sprintf("%s -> %s", name, s.link)
}

func (s *linkEntry) IsDir() bool {
	return false
}

func (s *linkEntry) Type() fs.FileMode {
	return TarHeader(s.fm).FileInfo().Mode()
}

func (s *linkEntry) Info() (fs.FileInfo, error) {
	return TarHeader(s.fm).FileInfo(), nil
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

func TarHeader(fm *ztoc.FileMetadata) *tar.Header {
	return &tar.Header{
		Typeflag: TarType(fm.Type),
		Name:     fm.Name,
		Linkname: fm.Linkname,

		Size:  int64(fm.UncompressedSize),
		Mode:  fm.Mode,
		Uid:   fm.UID,
		Gid:   fm.GID,
		Uname: fm.Uname,
		Gname: fm.Gname,

		ModTime: fm.ModTime,

		Devmajor: fm.Devmajor,
		Devminor: fm.Devminor,

		Xattrs: fm.Xattrs,
	}
}

func TarType(t string) byte {
	switch t {
	case "hardlink":
		return tar.TypeLink
	case "symlink":
		return tar.TypeSymlink
	case "dir":
		return tar.TypeDir
	case "reg":
		return tar.TypeReg
	case "char":
		return tar.TypeChar
	case "block":
		return tar.TypeBlock
	case "fifo":
		return tar.TypeFifo
	default:
		return tar.TypeReg
	}
}

func isLink(fm *ztoc.FileMetadata) bool {
	return fm.Linkname != ""
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
