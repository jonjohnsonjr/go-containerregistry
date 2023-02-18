package soci

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-containerregistry/internal/and"
	"github.com/google/go-containerregistry/internal/compress/gzip"
	"github.com/google/go-containerregistry/internal/httpserve"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// More than enough for FileServer to Peek at file contents.
const bufferLen = 2 << 16

type RenderDir func(w http.ResponseWriter, fname string, prefix string, mediaType types.MediaType, size int64, ref name.Reference, f httpserve.File, ctype string) error

type MultiFS struct {
	fss    []*SociFS
	prefix string

	lastFs   *SociFS
	lastFile string

	ref name.Reference

	Render    RenderDir
	MediaType types.MediaType
	Size      int64
}

func NewMultiFS(fss []*SociFS, prefix string, ref name.Reference) *MultiFS {
	filtered := []*SociFS{}
	for _, fs := range fss {
		if fs != nil {
			filtered = append(filtered, fs)
		}
	}
	return &MultiFS{
		fss:    filtered,
		prefix: prefix,
		ref:    ref,
	}
}

func (s *MultiFS) RenderHeader(w http.ResponseWriter, fname string, f httpserve.File, ctype string) error {
	logs.Debug.Printf("s.lastFile=%q, s.lastFs=%v, fname=%q", s.lastFile, s.lastFs == nil, fname)
	stat, err := f.Stat()
	if err != nil {
		return err
	}
	if stat.IsDir() {
		return s.Render(w, fname, s.prefix, s.MediaType, s.Size, s.ref, f, ctype)
	}

	if s.lastFs == nil {
		return fmt.Errorf("something went wrong")
	}
	return s.lastFs.RenderHeader(w, fname, f, ctype)

}

func (s *MultiFS) err(name string) fs.File {
	return &multiFile{
		fs:   s,
		name: name,
	}
}

func (s *MultiFS) chase(original string, gen int) (*TOCFile, *SociFS, error) {
	logs.Debug.Printf("multifs.chase(%q, %d)", original, gen)
	if original == "" {
		return nil, nil, fmt.Errorf("empty string")
	}
	if gen > 64 {
		log.Printf("chase(%q) aborting at gen=%d", original, gen)
		return nil, nil, fmt.Errorf("too many symlinks")
	}
	for _, sfs := range s.fss {
		chased, next, err := sfs.chase(original, gen)
		if err == fs.ErrNotExist {
			if next != original && next != "" {
				return s.chase(next, gen+1)
			}
			continue
		}
		return chased, sfs, err
	}

	return nil, nil, fs.ErrNotExist
}

func (s *MultiFS) find(name string) (*TOCFile, *SociFS, error) {
	logs.Debug.Printf("multifs.find(%q)", name)
	needle := path.Clean("/" + name)
	for _, sfs := range s.fss {
		for _, fm := range sfs.files {
			if path.Clean("/"+fm.Name) == needle {
				logs.Debug.Printf("returning %q (%d bytes)", fm.Name, fm.Size)
				return &fm, sfs, nil
			}
		}
	}

	return nil, nil, fs.ErrNotExist
}

func (s *MultiFS) Open(original string) (fs.File, error) {
	s.lastFile = original
	logs.Debug.Printf("multifs.Open(%q)", original)
	name := strings.TrimPrefix(original, s.prefix)

	chunks := strings.Split(name, " -> ")
	name = chunks[len(chunks)-1]
	name = strings.TrimPrefix(name, "/")
	logs.Debug.Printf("multifs.Opening(%q)", name)

	fm, sfs, err := s.find(name)
	if err != nil {
		logs.Debug.Printf("multifs.Open(%q) = %v", name, err)

		base := path.Base(name)
		if base == "index.html" || base == "favicon.ico" {
			return nil, fs.ErrNotExist
		}

		fm, sfs, err = s.chase(name, 0)
		if err != nil {
			if sfs == nil {
				// Possibly a directory?
				return s.err(name), nil
			}
			s.lastFs = sfs
			return sfs.err(name), nil
		}

		if fm.Typeflag == tar.TypeDir {
			logs.Debug.Printf("dir for %q = %q", name, fm.Name)
			return sfs.dir(fm), nil
		}

		name = path.Clean("/" + fm.Name)
	}
	s.lastFs = sfs

	if int64(fm.Size) > sfs.maxSize {
		logs.Debug.Printf("multifs.Open(%q): too big: %d", name, fm.Size)
		return sfs.tooBig(fm), nil
	}

	if fm.Typeflag == tar.TypeDir {
		// Return a multifs dir file so we search everything
		logs.Debug.Printf("multifs dir for %q = %q", name, fm.Name)
		return s.dir(fm), nil
	}

	return &sociFile{fs: sfs, name: name, fm: fm}, nil
}

func (s *MultiFS) dir(fm *TOCFile) fs.File {
	return &multiFile{
		fs:   s,
		name: fm.Name,
		fm:   fm,
	}
}

type multiFile struct {
	fs   *MultiFS
	name string
	fm   *TOCFile
}

func (s *multiFile) Stat() (fs.FileInfo, error) {
	logs.Debug.Printf("multifs.Stat(%q)", s.name)
	if s.fm != nil {
		s.fm.Name = strings.TrimPrefix(s.fm.Name, "./")
		s.fm.Name = strings.TrimPrefix(s.fm.Name, "/")
		logs.Debug.Printf("s.fm.Name = %q", s.fm.Name)
		return TarHeader(s.fm).FileInfo(), nil
	}

	// We don't have an entry, so we need to synthesize one.
	return &dirInfo{s.name}, nil
}

func (s *multiFile) Read(p []byte) (int, error) {
	logs.Debug.Printf("multifs.Read(%q)", s.name)
	return 0, fmt.Errorf("should not be called")
}

func (s *multiFile) Seek(offset int64, whence int) (int64, error) {
	logs.Debug.Printf("multifs.Seek(%q)", s.name)
	return 0, fmt.Errorf("should not be called")
}

func (s *multiFile) ReadDir(n int) ([]fs.DirEntry, error) {
	logs.Debug.Printf("multifs.ReadDir(%q)", s.name)
	have := map[string]struct{}{}
	realDirs := map[string]struct{}{}
	implicitDirs := map[string]struct{}{}
	de := []fs.DirEntry{}
	if s.name == "." || s.name == "/" || s.name == "" || s.name == "./" {
		logs.Debug.Printf("I think this is root")
	} else {
		de = append(de, &sociDirEntry{nil, "..", nil})
	}
	subdir := strings.TrimSuffix(strings.TrimPrefix(s.name, "./"), "/")
	for i, sfs := range s.fs.fss {
		des, reald, implicitd, err := sfs.readDir(subdir)
		if err != nil {
			return nil, err
		}
		for i := range reald {
			realDirs[i] = struct{}{}
		}
		for i := range implicitd {
			implicitDirs[i] = struct{}{}
		}
		sawOpaque := false
		for _, got := range des {
			name := got.Name()

			if name == ".wh..wh..opq" {
				logs.Debug.Printf("multifs.ReadDir(%q): saw opaque whiteout in layer[%d]", s.name, i)
				sawOpaque = true
			}
			if _, ok := have[name]; !ok {
				have[name] = struct{}{}
				if _, ok := have[".wh."+name]; ok {
					logs.Debug.Printf("saw whiteout for %q, skipping", name)
				} else if strings.HasPrefix(name, ".wh.") {
					logs.Debug.Printf("do not return whiteout %q", name)
				} else {
					de = append(de, got)
				}
			}
		}
		if sawOpaque {
			break
		}
	}

	for dir := range implicitDirs {
		if _, ok := realDirs[dir]; !ok {
			logs.Debug.Printf("Adding implicit dir: %s", dir)
			de = append(de, &sociDirEntry{nil, dir, nil})
		}
	}

	logs.Debug.Printf("len(multifs.ReadDir(%q)) = %d", s.name, len(de))
	return de, nil
}

func (s *multiFile) Close() error {
	return nil
}

type BlobSeeker interface {
	Reader(ctx context.Context, off int64, end int64) (io.ReadCloser, error)
}

func FS(tree Tree, bs BlobSeeker, prefix string, ref string, maxSize int64) *SociFS {
	return &SociFS{
		tree:    tree,
		files:   tree.TOC().Files,
		bs:      bs,
		maxSize: maxSize,
		prefix:  prefix,
		ref:     ref,
	}
}

type RenderFunc func(w http.ResponseWriter, fname string, prefix string, ref name.Reference, kind string, size int64, f httpserve.File, ctype string) error

type SociFS struct {
	files []TOCFile

	bs BlobSeeker

	tree Tree

	prefix  string
	ref     string
	maxSize int64

	Render RenderFunc
}

func (s *SociFS) RenderHeader(w http.ResponseWriter, fname string, f httpserve.File, ctype string) error {
	if s.Render != nil {
		ref, err := name.ParseReference(s.ref)
		if err != nil {
			return err
		}
		kind := "targz"
		if toc := s.tree.TOC(); toc != nil && toc.Type != "" {
			kind = toc.Type
		}
		return s.Render(w, fname, s.prefix, ref, kind, s.tree.TOC().Csize, f, ctype)
	}
	return nil
}

func (s *SociFS) extractFile(ctx context.Context, tf *TOCFile) (io.ReadCloser, error) {
	return ExtractTreeFile(ctx, s.tree, s.bs, tf)
}

func (s *SociFS) err(name string) fs.File {
	return &sociFile{
		fs:   s,
		name: name,
	}
}

func (s *SociFS) dir(fm *TOCFile) fs.File {
	return &sociFile{
		fs:   s,
		name: fm.Name,
		fm:   fm,
	}
}

func (s *SociFS) tooBig(fm *TOCFile) fs.File {
	crane := fmt.Sprintf("crane blob %s | gunzip | tar -Oxf - %s", s.ref, fm.Name)
	data := []byte("this file is too big, use crane to download it:\n\n" + crane)
	fm.Size = int64(len(data))

	return &sociFile{
		fs:   s,
		name: fm.Name,
		fm:   fm,
		buf:  bufio.NewReader(bytes.NewReader(data)),
	}
}

func (s *SociFS) Open(original string) (fs.File, error) {
	logs.Debug.Printf("soci.Open(%q)", original)
	name := strings.TrimPrefix(original, s.prefix)

	chunks := strings.Split(name, " -> ")
	name = chunks[len(chunks)-1]
	name = strings.TrimPrefix(name, "/")
	logs.Debug.Printf("soci.Opening(%q)", name)

	fm, err := s.find(name)
	if err != nil {
		logs.Debug.Printf("soci.Open(%q) = %v", name, err)

		base := path.Base(name)
		if base == "index.html" || base == "favicon.ico" {
			return nil, fs.ErrNotExist
		}

		chased, _, err := s.chase(name, 0)
		if err != nil {
			// Possibly a directory?
			return s.err(name), nil
		}

		if chased.Typeflag == tar.TypeDir {
			return s.dir(chased), nil
		}

		name = path.Clean("/" + chased.Name)
		fm = chased
	}

	if int64(fm.Size) > s.maxSize {
		logs.Debug.Printf("soci.Open(%q): too big: %d", name, fm.Size)
		return s.tooBig(fm), nil
	}

	return &sociFile{fs: s, name: name, fm: fm}, nil
}

func (s *SociFS) ReadDir(original string) ([]fs.DirEntry, error) {
	logs.Debug.Printf("soci.ReadDir(%q)", original)
	dir := strings.TrimPrefix(original, s.prefix)
	if dir != original {
		logs.Debug.Printf("soci.ReadDir(%q)", dir)
	}

	// Implicit directories.
	de, realDirs, implicitDirs, err := s.readDir(original)
	if err != nil {
		return nil, err
	}

	if dir == "." || dir == "/" || dir == "" || dir == "./" {
		logs.Debug.Printf("I think this is root")
	} else {
		de = append(de, s.dirEntry("..", nil))
	}

	for dir := range implicitDirs {
		if _, ok := realDirs[dir]; !ok {
			logs.Debug.Printf("Adding implicit dir: %s", dir)
			de = append(de, s.dirEntry(dir, nil))
		}
	}

	logs.Debug.Printf("len(ReadDir(%q)) = %d", dir, len(de))
	return de, nil
}

func (s *SociFS) readDir(original string) ([]fs.DirEntry, map[string]struct{}, map[string]struct{}, error) {
	logs.Debug.Printf("soci.ReadDir(%q)", original)
	dir := strings.TrimPrefix(original, s.prefix)
	if dir != original {
		logs.Debug.Printf("soci.ReadDir(%q)", dir)
	}

	// Implicit directories.
	implicitDirs := map[string]struct{}{}

	// Implicit directories.
	realDirs := map[string]struct{}{}

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
					implicitDirs[implicit] = struct{}{}
				}
			}
			continue
		}

		if fm.Typeflag == tar.TypeDir {
			dirname := s.dirEntry(dir, &fm).Name()
			if dirname[0] == '/' {
				dirname = dirname[1:]
			}
			realDirs[dirname] = struct{}{}
			de = append(de, s.dirEntry(dir, &fm))
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

	return de, realDirs, implicitDirs, nil
}

func (s *SociFS) find(name string) (*TOCFile, error) {
	logs.Debug.Printf("find(%q)", name)
	needle := path.Clean("/" + name)
	for _, fm := range s.files {
		if path.Clean("/"+fm.Name) == needle {
			logs.Debug.Printf("returning %q (%d bytes)", fm.Name, fm.Size)
			return &fm, nil
		}
	}

	return nil, fs.ErrNotExist
}

func (s *SociFS) dirEntry(dir string, fm *TOCFile) *sociDirEntry {
	return &sociDirEntry{s, dir, fm}
}

// todo: cache symlinks to require fewer iterations?
// todo: or maybe symlinks as separate list?
func (s *SociFS) chase(original string, gen int) (*TOCFile, string, error) {
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

	for _, fm := range s.files {
		fm := fm
		if fm.Name == original || fm.Name == name {
			if fm.Typeflag == tar.TypeSymlink {
				return s.chase(fm.Linkname, gen+1)
			}
			return &fm, "", nil
		}
		if fm.Typeflag == tar.TypeSymlink {
			for _, dir := range dirs {
				if fm.Name == dir {
					// todo: re-fetch header.Linkname/<rest>
					prefix := path.Clean("/" + fm.Name)
					next := path.Join(fm.Linkname, strings.TrimPrefix(name, prefix))
					return s.chase(next, gen+1)
				}
			}
		}
	}

	return nil, original, fs.ErrNotExist
}

type sociFile struct {
	fs     *SociFS
	name   string
	fm     *TOCFile
	buf    *bufio.Reader
	closer func() error

	// TODO: Figure out how to get rid of this nonsense.
	// The real cursor of the underlying file.
	cursor int64

	// The cursor FileServer thinks it has after a Peek.
	peeked int64
}

func (s *sociFile) Stat() (fs.FileInfo, error) {
	if s.fm != nil {
		if s.fm.Typeflag == tar.TypeSymlink {
			hdr := TarHeader(s.fm)
			hdr.Typeflag = tar.TypeDir
			return hdr.FileInfo(), nil
		}
		return TarHeader(s.fm).FileInfo(), nil
	}

	// We don't have an entry, so we need to synthesize one.
	return &dirInfo{s.name}, nil
}

func (s *sociFile) Read(p []byte) (int, error) {
	if s.fm != nil && s.fm.Size == 0 {
		return 0, io.EOF
	}
	logs.Debug.Printf("soci.Read(%q): len(p) = %d", s.name, len(p))
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
	logs.Debug.Printf("soci.Read(%q): f.peeked=%d, f.header.size=%d", s.name, s.peeked, s.fm.Size)
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
	logs.Debug.Printf("soci.Read(%q) at the end", s.name)
	// TODO: Only read s.fm.Size ever
	return s.buf.Read(p)
}

func (s *sociFile) Seek(offset int64, whence int) (int64, error) {
	logs.Debug.Printf("soci.Open(%q).Seek(%d, %d) @ [%d, %d]", s.name, offset, whence, s.cursor, s.peeked)
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

func (s *sociFile) ReadDir(n int) ([]fs.DirEntry, error) {
	logs.Debug.Printf("sociFile.ReadDir")
	if s.fm != nil && s.fm.Typeflag == tar.TypeSymlink {
		fm := *s.fm
		fm.Name = "."

		return []fs.DirEntry{&linkEntry{
			fs:   s.fs,
			fm:   &fm,
			link: fm.Linkname,
		}}, nil
	}
	return s.fs.ReadDir(s.name)
}

func (s *sociFile) Close() error {
	if s.closer != nil {
		return s.closer()
	}
	return nil
}

type sociDirEntry struct {
	fs  *SociFS
	dir string
	fm  *TOCFile
}

func (s *sociDirEntry) Name() string {
	if s.fm == nil {
		return s.dir
	}
	trimmed := strings.TrimPrefix(s.fm.Name, "./")
	if s.dir != "" && !strings.HasPrefix(s.dir, "/") && strings.HasPrefix(trimmed, "/") {
		trimmed = strings.TrimPrefix(trimmed, "/"+s.dir+"/")
	} else {
		trimmed = strings.TrimPrefix(trimmed, s.dir+"/")
	}
	return path.Clean(trimmed)
}

func (s *sociDirEntry) IsDir() bool {
	if s.fm == nil {
		return true
	}
	return s.fm.Typeflag == tar.TypeDir
}

func (s *sociDirEntry) Type() fs.FileMode {
	if s.fm == nil {
		return (&dirInfo{s.dir}).Mode()
	}
	return TarHeader(s.fm).FileInfo().Mode()
}

func (s *sociDirEntry) Info() (fs.FileInfo, error) {
	if s.fm == nil {
		return &dirInfo{s.dir}, nil
	}
	return TarHeader(s.fm).FileInfo(), nil
}

func (s *sociDirEntry) Layer() string {
	if s.fs != nil {
		return s.fs.ref
	}
	return ""
}

type linkEntry struct {
	fs   *SociFS
	fm   *TOCFile
	dir  string
	link string
}

func (s *linkEntry) Layer() string {
	if s.fs != nil {
		return s.fs.ref
	}
	return ""
}

func (s *linkEntry) Name() string {
	trimmed := strings.TrimPrefix(s.fm.Name, "./")
	if s.dir != "" && !strings.HasPrefix(s.dir, "/") && strings.HasPrefix(trimmed, "/") {
		trimmed = strings.TrimPrefix(trimmed, "/"+s.dir+"/")
	} else {
		trimmed = strings.TrimPrefix(trimmed, s.dir+"/")
	}
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

func isLink(fm *TOCFile) bool {
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

func TarHeader(header *TOCFile) *tar.Header {
	return &tar.Header{
		Typeflag: header.Typeflag,
		Name:     header.Name,
		Linkname: header.Linkname,
		Size:     header.Size,
		Mode:     header.Mode,
		ModTime:  header.ModTime,
		Uid:      header.Uid,
		Gid:      header.Gid,
	}
}

// TODO: Make this a better API.
func ExtractFile(ctx context.Context, bs BlobSeeker, index *Index, tf *TOCFile) (io.ReadCloser, error) {
	logs.Debug.Printf("ExtractFile %T", bs)
	if tf.Size == 0 {
		return io.NopCloser(bytes.NewReader([]byte{})), nil
	}

	logs.Debug.Printf("file is at %d", tf.Offset)

	from := index.Checkpoints[0]
	discard := int64(0)
	for i, c := range index.Checkpoints {
		logs.Debug.Printf("%s", c.String())
		if c.Out > tf.Offset {
			discard = tf.Offset - from.Out
			break
		}
		if i == len(index.Checkpoints)-1 {
			discard = tf.Offset - c.Out
		}
		from = index.Checkpoints[i]
	}
	start := from.In
	uend := tf.Offset + tf.Size

	logs.Debug.Printf("start=%d, uend=%d", start, uend)

	end := index.Csize
	for _, c := range index.Checkpoints {
		logs.Debug.Printf("%s", c.String())
		if c.Out > uend {
			end = c.In
			break
		}
	}

	logs.Debug.Printf("end=%d", end)

	rc, err := bs.Reader(ctx, start, end)
	if err != nil {
		return nil, err
	}

	logs.Debug.Printf("Calling gzip.Continue")
	r, err := gzip.Continue(rc, 1<<22, &from, nil)
	if err != nil {
		return nil, err
	}

	logs.Debug.Printf("discarding %d bytes", discard)

	if _, err := io.CopyN(io.Discard, r, discard); err != nil {
		return nil, err
	}

	lr := io.LimitedReader{r, tf.Size}

	logs.Debug.Printf("returning limitedreader of size %d", tf.Size)

	return &and.ReadCloser{&lr, rc.Close}, nil
}

func strikethrough(s string) string {
	var b strings.Builder
	b.Grow(2 * len(s))
	b.WriteRune('\u0336')
	for _, c := range s {
		b.WriteRune(c)
		b.WriteRune('\u0336')
	}

	return b.String()
}

func unstrikethrough(s string) string {
	var b strings.Builder
	b.Grow(len(s) / 2)
	for _, c := range s {
		if c != '\u0336' {
			b.WriteRune(c)
		}
	}

	return b.String()
}
