package main

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/google/go-containerregistry/pkg/v1/v1util"
)

const debug = false

const indexTemplate = `
<div style="font-family: monospace;">
{
	<div style="margin-left: 2em;">
	<div>
	"schemaVersion": {{.SchemaVersion}},
	</div>
	<div>
	"mediaType": "{{.MediaType}}",
	</div>
	<div>
	"manifests": [
	{{ range .Manifests }}
	<div style="margin-left: 2em;">
	{
		<div style="margin-left: 2em;">
		<div>
		"mediaType": "{{.MediaType}}",
		</div>
		<div>
		"size": {{.Size}},
		</div>
		<div>
		"digest": <a href="/?image={{$.Repo}}@{{.Digest}}">{{.Digest}}</a>,
		</div>
		{{ if .Platform }}
		{{ with .Platform }}
		<div>
		"platform": {
			<div style="margin-left: 2em;">
			<div>
			"architecture": "{{.Architecture}}",
			</div>
			<div>
			"os": "{{.OS}}",
			</div>
			{{ if .OSVersion }}
			<div>
			"os.version": "{{.OSVersion}}",
			</div>
			{{end}}
			{{ if .OSFeatures }}
			<div>
			"os.features": [
				<div style="margin-left: 2em;">
				{{range .OSFeatures}}
					<div>
					"{{.}}",
					</div>
				{{end}}
			</div>
			],
			</div>
			{{end}}
			{{ if .Variant }}
			<div>
			"variant": "{{.Variant}}"
			</div>
			{{end}}
			</div>
		}
		</div>
		{{end}}
		{{end}}
		</div>
	},
	</div>
	{{ end }}
	]
	</div>
	</div>
}
</div>
`

const manifestTemplate = `
<div style="font-family: monospace;">
{
	<div style="margin-left: 2em;">
	<div>
	"schemaVersion": {{.SchemaVersion}},
	</div>
	<div>
	"mediaType": "{{.MediaType}}",
	</div>
	<div>
	"config": {
		{{ with .Config }}
		<div style="margin-left: 2em;">
		<div>
		"mediaType": "{{.MediaType}}",
		</div>
		<div>
		"size": {{.Size}},
		</div>
		<div>
		"digest": <a href="/?config={{$.Repo}}@{{.Digest}}&image={{$.Image}}">{{.Digest}}</a>,
		</div>
		</div>
		{{ end }}
	}
	</div>
	<div>
	"layers": [
	{{ range .Layers }}
	<div style="margin-left: 2em;">
	{
		<div style="margin-left: 2em;">
		<div>
		"mediaType": "{{.MediaType}}",
		</div>
		<div>
		"size": {{.Size}},
		</div>
		<div>
		"digest": <a href="/fs/{{$.Repo}}@{{.Digest}}">{{.Digest}}</a>,
		</div>
		</div>
	},
	</div>
	{{ end }}
	]
	</div>
	</div>
}
</div>
`

type IndexData struct {
	Repo string
	v1.IndexManifest
}

type ManifestData struct {
	Repo  string
	Image string
	v1.Manifest
}

func handler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%v", r.URL.Query())

	if err := renderResponse(w, r); err != nil {
		fmt.Fprintf(w, "failed: %v", err)
	}
}

func main() {
	log.Print("Hello world sample started.")

	http.HandleFunc("/", handler)
	http.HandleFunc("/fs/", fsHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}

func renderResponse(w http.ResponseWriter, r *http.Request) error {
	qs := r.URL.Query()

	if configs, ok := qs["config"]; ok {
		return renderConfig(w, configs[0])
	}

	images, ok := qs["image"]
	if !ok {
		return errors.New("expected 'image' in query string")
	}
	image := images[0]

	ref, err := name.ParseReference(image, name.WeakValidation)
	if err != nil {
		return err
	}
	desc, err := remote.Get(ref)
	if err != nil {
		return err
	}

	if desc.MediaType == types.DockerManifestList || desc.MediaType == types.OCIImageIndex {
		return renderIndex(w, desc, ref)
	} else if desc.MediaType == types.DockerManifestSchema2 || desc.MediaType == types.OCIManifestSchema1 {
		return renderImage(w, desc, ref)
	}

	return fmt.Errorf("unimplemented mediaType: %s", desc.MediaType)
}

func renderIndex(w io.Writer, desc *remote.Descriptor, ref name.Reference) error {
	index, err := desc.ImageIndex()
	if err != nil {
		return err
	}

	manifest, err := index.IndexManifest()
	if err != nil {
		return err
	}

	data := IndexData{
		Repo:          ref.Context().String(),
		IndexManifest: *manifest,
	}

	tmpl, err := template.New("indexTemplate").Parse(indexTemplate)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, data)
}

func renderImage(w io.Writer, desc *remote.Descriptor, ref name.Reference) error {
	img, err := desc.Image()
	if err != nil {
		return err
	}

	manifest, err := img.Manifest()
	if err != nil {
		return err
	}

	data := ManifestData{
		Repo:     ref.Context().String(),
		Image:    ref.String(),
		Manifest: *manifest,
	}

	tmpl, err := template.New("manifestTemplate").Parse(manifestTemplate)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, data)
}

func renderConfig(w io.Writer, ref string) error {
	cfgRef, err := name.ParseReference(ref, name.StrictValidation)
	if err != nil {
		return err
	}

	blob, err := remote.Blob(cfgRef)
	if err != nil {
		return err
	}

	_, err = io.Copy(w, blob)
	return err
}

func fsHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%v", r.URL)

	ref := strings.TrimPrefix(r.URL.Path, "/fs/")
	if err := renderBlob(w, r, ref); err != nil {
		fmt.Fprintf(w, "failed: %v", err)
	}
}

func renderBlob(w http.ResponseWriter, r *http.Request, path string) error {
	chunks := strings.Split(path, "@")
	if len(chunks) != 2 {
		return fmt.Errorf("not enough chunks: %s", path)
	}
	// 71 = len("sha256:") + 64
	if len(chunks[1]) < 71 {
		return fmt.Errorf("second chunk too short: %s", chunks[1])
	}

	ref := strings.Join([]string{chunks[0], chunks[1][:71]}, "@")
	if ref == "" {
		return nil
	}
	blobRef, err := name.ParseReference(ref, name.StrictValidation)
	if err != nil {
		return err
	}

	blob, err := remote.Blob(blobRef)
	if err != nil {
		return err
	}

	zr, err := v1util.GunzipReadCloser(blob)
	if err != nil {
		return err
	}
	defer zr.Close()

	fs := &layerFs{
		ref: ref,
		tr:  tar.NewReader(zr),
	}

	http.FileServer(fs).ServeHTTP(w, r)

	return nil
}

type layerFs struct {
	ref     string
	tr      *tar.Reader
	headers []*tar.Header
}

func (fs *layerFs) Open(name string) (http.File, error) {
	log.Printf("Open(%q)", name)
	name = strings.TrimPrefix(name, "/fs/"+fs.ref)
	chunks := strings.Split(name, " -> ")
	if len(chunks) == 2 {
		name = chunks[1]
		log.Printf("Open(%q) (scrubbed)", name)
	}
	for {
		header, err := fs.tr.Next()
		if err == io.EOF {
			log.Printf("Open(%q): EOF", name)
			break
		}
		log.Printf("Open(%q): header.Name = %q", name, header.Name)
		fs.headers = append(fs.headers, header)
		if err != nil {
			return nil, err
		}
		if path.Clean("/"+header.Name) == name {
			return &layerFile{
				name:   name,
				header: header,
				fs:     fs,
			}, nil
		}
	}

	if path.Base(name) == "index.html" {
		return nil, fmt.Errorf("nope: %s", name)
	}

	// Assume we're listing the top level, return this thing.
	return &layerFile{
		name: name,
		fs:   fs,
	}, nil
}

type layerFile struct {
	name   string
	header *tar.Header
	fs     *layerFs
	br     *bytes.Reader
	bytes  []byte
}

func (f *layerFile) Seek(offset int64, whence int) (int64, error) {
	log.Printf("Seek(%q, %d, %d)", f.name, offset, whence)
	if whence == io.SeekEnd {
		return f.header.Size, nil
	}
	if whence == io.SeekStart {
		f.br = bytes.NewReader(f.bytes)
		log.Printf("f.br = bytes.NewReader(f.bytes)")
		return 0, nil
	}

	return 0, fmt.Errorf("Seek(%q, %d, %d)", f.name, offset, whence)
}

func (f *layerFile) Read(b []byte) (int, error) {
	if f.br == nil {
		b, err := ioutil.ReadAll(f.fs.tr)
		if err != nil {
			return 0, err
		}
		log.Printf("ReadAll(%q) = %d bytes", f.name, len(b))
		f.bytes = b
		f.br = bytes.NewReader(f.bytes)
	}
	n, err := f.br.Read(b)
	log.Printf("Read(%q) = (%d, %v)", f.name, n, err)
	return n, err
}

func (f *layerFile) Close() error {
	log.Printf("Close(%q)", f.name)
	return nil
}

func (f *layerFile) Readdir(count int) ([]os.FileInfo, error) {
	log.Printf("ReadDir(%q)", f.name)
	prefix := path.Clean("/" + f.name)
	if f.Root() {
		prefix = "/"
	}
	// TODO: respect count
	fis := []os.FileInfo{}
	for _, hdr := range f.fs.headers {
		name := path.Clean("/" + hdr.Name)
		dir := path.Dir(strings.TrimPrefix(name, prefix))
		if debug {
			log.Printf("hdr.Name=%q prefix=%q name=%q dir=%q", hdr.Name, prefix, name, dir)
		}
		// inDir := path.Clean("/"+dir+"/") == path.Clean("/"+name+"/")
		if strings.HasPrefix(name, prefix) && (f.Root() && dir == "." || dir == "/") {
			if debug {
				log.Printf("Readdir(%q) -> %q match!", f.name, hdr.Name)
			}
			fi := hdr.FileInfo()
			if isLink(hdr) {
				link := hdr.Linkname
				if !path.IsAbs(hdr.Linkname) {
					if f.Root() && dir == "." {
						dir = "/"
					}
					link = path.Clean(path.Join(dir, link))
				}
				fi = symlink{
					FileInfo: fi,
					name:     fi.Name(),
					link:     link,
				}
			}
			fis = append(fis, fi)
		}
	}
	return fis, nil
}

func isLink(hdr *tar.Header) bool {
	return hdr.Linkname != ""
}

func (f *layerFile) Stat() (os.FileInfo, error) {
	log.Printf("Stat(%q)", f.name)
	if f.Root() {
		return fileInfo{f.name}, nil
	}
	return f.header.FileInfo(), nil
}

func (f *layerFile) Root() bool {
	return f.name == "" || f.name == "/" || f.name == "/index.html"
}

type fileInfo struct {
	name string
}

func (f fileInfo) Name() string {
	return f.name
}

func (f fileInfo) Size() int64 {
	return 0
}

func (f fileInfo) Mode() os.FileMode {
	return os.ModeDir
}

func (f fileInfo) ModTime() time.Time {
	return time.Now()
}

func (f fileInfo) IsDir() bool {
	return true
}

func (f fileInfo) Sys() interface{} {
	return nil
}

type symlink struct {
	os.FileInfo
	name string
	link string
}

func (s symlink) Name() string {
	return fmt.Sprintf("%s -> %s", s.name, s.link)
}
