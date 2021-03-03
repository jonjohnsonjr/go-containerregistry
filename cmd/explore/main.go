package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/google/go-containerregistry/pkg/v1/v1util"
)

const debug = false

const headerTemplate = `
<html>
<body>
<head>
<style>
.mt:hover {
	text-decoration: underline;
}
	
.mt {
  color: inherit;
	text-decoration: inherit; 
}
</style>
</head>
<div style="font-family: monospace;">
<h2>{{.Reference}}{{ if .CosignTag }} (<a href="?image={{.Repo}}:{{.CosignTag}}">cosign</a>){{end}}</h2>
Docker-Content-Digest: {{.Descriptor.Digest}}<br>
Content-Length: {{.Descriptor.Size}}<br>
Content-Type: {{.Descriptor.MediaType}}<br>
</div>
<hr>
`
const footerTemplate = `
</body>
</html>
`

const indexTemplate = headerTemplate + `
<div style="font-family: monospace;">
{
	<div style="margin-left: 2em;">
	<div>
	"schemaVersion": {{.SchemaVersion}},
	</div>
	{{ if .MediaType }}
	<div>
	"mediaType": "<a class="mt" href="{{ mediaTypeLink .MediaType }}">{{.MediaType}}</a>",
	</div>
	{{end}}
	<div>
	"manifests": [
	{{ range $i, $manifest := .Manifests }}
	<div style="margin-left: 2em;">
	{
		<div style="margin-left: 2em;">
		<div>
		"mediaType": "<a class="mt" href="{{ mediaTypeLink .MediaType }}">{{.MediaType}}</a>",
		</div>
		<div>
		"size": {{.Size}},
		</div>
		<div>
		"digest": "<a href="/{{handlerForMT .MediaType}}{{$.Repo}}@{{.Digest}}">{{.Digest}}</a>"{{ if (or .Platform .Annotations .URLs) }},{{ end }}
		</div>
		{{ if .Platform }}
		{{ with .Platform }}
		<div>
		"platform": {
			<div style="margin-left: 2em;">
			<div>
			"architecture": "{{.Architecture}}"{{ if .OS }},{{end}}
			</div>
			<div>
			"os": "{{.OS}}"{{ if .OSVersion }},{{end}}
			</div>
			{{ if .OSVersion }}
			<div>
			"os.version": "{{.OSVersion}}"{{ if .OSFeatures }},{{end}}
			</div>
			{{end}}
			{{ if .OSFeatures }}
			<div>
			"os.features": [
				<div style="margin-left: 2em;">
				{{range $i, $e := .OSFeatures}}
					<div>
					"{{.}}"{{ if not (last $i .OSFeatures) }},{{ end }}
					</div>
				{{end}}
			</div>
			]{{if .Variant}},{{end}}
			</div>
			{{end}}
			{{ if .Variant }}
			<div>
			"variant": "{{.Variant}}"{{if .Features}},{{end}}
			</div>
			{{end}}
			</div>
			{{ if .Features }}
			<div>
			"features": [
				<div style="margin-left: 2em;">
				{{range $i, $e := .Features}}
					<div>
					"{{.}}"{{ if not (last $i $.Features) }},{{ end }}
					</div>
				{{end}}
			</div>
			]
			</div>
			{{end}}
		}{{ if $manifest.Annotations }},{{ end }}
		{{end}}
		</div>
		{{ if $manifest.Annotations }}
		<div>
		"annotations": {
			<div style="margin-left: 2em;">
			{{range $k, $v := $manifest.Annotations}}
				<div>
				"{{$k}}": "{{$v}}"{{ if not (mapLast $k $manifest.Annotations) }},{{ end }}
				</div>
			{{end}}
		</div>
		}
		</div>
		{{end}}
		{{end}}
		</div>
	}{{ if not (last $i $.Manifests) }},{{ end }}
	</div>
	{{ end }}
	]{{ if $.Annotations }},
	<div>
	"annotations": {
		<div style="margin-left: 2em;">
		{{range $k, $v := $.Annotations}}
			<div>
			"{{$k}}": "{{$v}}"{{ if not (mapLast $k $.Annotations) }},{{ end }}
			</div>
		{{end}}
	}
	</div>
	{{end}}
	</div>
	</div>
}
</div>
` + footerTemplate

const manifestTemplate = headerTemplate + `
<div style="font-family: monospace;">
{
	<div style="margin-left: 2em;">
	<div>
	"schemaVersion": {{.SchemaVersion}},
	</div>
	<div>
	"mediaType": "<a class="mt" href="{{ mediaTypeLink .MediaType }}">{{.MediaType}}</a>",
	</div>
	<div>
	"config": {
		{{ with .Config }}
		<div style="margin-left: 2em;">
		<div>
		"mediaType": "<a class="mt" href="{{ mediaTypeLink .MediaType }}">{{.MediaType}}</a>",
		</div>
		<div>
		"size": {{.Size}},
		</div>
		<div>
		"digest": "<a href="/{{handlerForMT .MediaType}}{{$.Repo}}@{{.Digest}}&image={{$.Image}}">{{.Digest}}</a>"{{ if (or .Platform .Annotations .URLs) }},{{end}}
		</div>
		{{ if .Annotations }}
		<div>
		"annotations": {
			<div style="margin-left: 2em;">
			{{range $k, $v := .Annotations}}
				<div>
				"{{$k}}": "{{$v}}"{{ if not (mapLast $k .Annotations) }},{{ end }}
				</div>
			{{end}}
		</div>
		}
		</div>
		{{end}}
		</div>
		{{ end }}
	},
	</div>
	<div>
	"layers": [
	{{ range $i, $layer := .Layers }}
	<div style="margin-left: 2em;">
	{
		<div style="margin-left: 2em;">
		<div>
		"mediaType": "<a class="mt" href="{{ mediaTypeLink .MediaType }}">{{.MediaType}}</a>",
		</div>
		<div>
		"size": {{.Size}},
		</div>
		<div>
		"digest": "<a href="/{{handlerForMT .MediaType}}{{$.Repo}}@{{.Digest}}">{{.Digest}}</a>"{{ if (or $layer.Annotations $layer.Platform $layer.URLs) }},{{end}}
		</div>
		{{ if $layer.URLs }}
		<div>
		"urls": [
			<div style="margin-left: 2em;">
			{{range $j, $url := $layer.URLs}}
				<div>
				"{{$url}}"{{ if not (last $j $layer.URLs) }},{{ end }}
				</div>
			{{end}}
		</div>
		]{{ if $layer.Annotations }},{{end}}
		</div>
		{{end}}
		{{ if $layer.Annotations }}
		<div>
		"annotations": {
			<div style="margin-left: 2em;">
			{{range $k, $v := $layer.Annotations}}
				<div>
				"{{$k}}": "{{$v}}"{{ if not (mapLast $k $layer.Annotations) }},{{ end }}
				</div>
			{{end}}
		</div>
		}
		</div>
		{{end}}
		</div>
	}{{ if not (last $i $.Layers) }},{{ end }}
	</div>
	{{ end }}
	]{{ if $.Annotations }},
	<div>
	"annotations": {
		<div style="margin-left: 2em;">
		{{range $k, $v := $.Annotations}}
			<div>
			"{{$k}}": "{{$v}}"{{ if not (mapLast $k $.Annotations) }},{{ end }}
			</div>
		{{end}}
	}
	</div>
	{{end}}

	</div>
	</div>
}
` + footerTemplate

const cosignTemplate = `
<html>
<body>
<head>
<style>
.mt:hover {
	text-decoration: underline;
}
	
.mt {
  color: inherit;
	text-decoration: inherit; 
}
</style>
</head>

<div style="font-family: monospace;">
{
	<div style="margin-left: 2em;">
	<div>
	"Critical": {
		<div style="margin-left: 2em;">
		<div>
		"Identity": {
			<div style="margin-left: 2em;">
				"docker-reference": "{{.Critical.Identity.DockerReference}}"
			</div>
		},
		</div>
		<div>
		"Image": {
			<div style="margin-left: 2em;">
				"Docker-manifest-digest": "<a href="/?image={{$.Repo}}@{{.Critical.Image.DockerManifestDigest}}&discovery=true">{{.Critical.Image.DockerManifestDigest}}</a>"
			</div>
		},
		</div>
		<div>
		"Type": "{{.Critical.Type}}"
		</div>
	</div>
	},
	</div>
	<div>
	"Optional": {{if .Optional}}{
		<div style="margin-left: 2em;">
		{{range $k, $v := $.Optional}}
			<div>
			"{{$k}}": "{{$v}}"{{ if not (mapLast $k $.Optional) }},{{ end }}
			</div>
		{{end}}
		</div>
	}{{else}}null{{end}}
	</div>
	</div>
	</div>
}
</div>
` + footerTemplate

const descriptorTemplate = `
<html>
<body>
<head>
<style>
.mt:hover {
	text-decoration: underline;
}
	
.mt {
  color: inherit;
	text-decoration: inherit; 
}
</style>
</head>

<div style="font-family: monospace;">
{
	<div style="margin-left: 2em;">
	<div>
	"mediaType": "<a class="mt" href="{{ mediaTypeLink .MediaType }}">{{.MediaType}}</a>",
	</div>
	<div>
	"size": {{.Size}},
	</div>
	<div>
	"digest": "<a href="/{{handlerForMT .MediaType}}{{$.Repo}}@{{.Digest}}">{{.Digest}}</a>"{{ if (or .Platform .Annotations .URLs) }},{{end}}
	</div>
	{{ if .Annotations }}
	<div>
	"annotations": {
		<div style="margin-left: 2em;">
		{{range $k, $v := .Annotations}}
			<div>
			"{{$k}}": "{{$v}}"{{ if not (mapLast $k $.Annotations) }},{{ end }}
			</div>
		{{end}}
	</div>
	}
	</div>
	{{end}}
	</div>
}
</div>
` + footerTemplate

var fns = template.FuncMap{
	"last": func(x int, a interface{}) bool {
		return x == reflect.ValueOf(a).Len()-1
	},
	"mapLast": func(x string, a interface{}) bool {
		// We know this is only used for map[string]string
		vs := reflect.ValueOf(a).MapKeys()
		ss := make([]string, 0, len(vs))
		for _, v := range vs {
			ss = append(ss, v.String())
		}
		sort.Strings(ss)
		return x == ss[len(ss)-1]
	},
	"mediaTypeLink": func(a interface{}) string {
		mt := reflect.ValueOf(a).String()
		return getLink(mt)
	},
	"handlerForMT": func(a interface{}) string {
		mt := reflect.ValueOf(a).String()
		return handlerForMT(mt)
	},
}

func handlerForMT(s string) string {
	mt := types.MediaType(s)
	if !mt.IsDistributable() {
		// TODO
		return `fs`
	}
	if mt.IsImage() {
		return `?image=`
	}
	if mt.IsIndex() {
		return `?image=`
	}
	switch mt {
	case types.OCIConfigJSON, types.DockerConfigJSON:
		return `?config=`
	case types.OCILayer, types.OCIUncompressedLayer, types.DockerLayer, types.DockerUncompressedLayer:
		return `fs/`
	case types.OCIContentDescriptor:
		return `?descriptor=`
	case `application/vnd.dev.cosign.simplesigning.v1+json`:
		return `?cosign=`
	}
	if strings.HasSuffix(s, "+json") {
		return `?config=`
	}
	return `fs/`
}

func getLink(s string) string {
	mt := types.MediaType(s)
	if !mt.IsDistributable() {
		return `https://github.com/opencontainers/image-spec/blob/master/layer.md#non-distributable-layers`
	}
	if mt.IsImage() {
		return `https://github.com/opencontainers/image-spec/blob/master/manifest.md`
	}
	if mt.IsIndex() {
		return `https://github.com/opencontainers/image-spec/blob/master/image-index.md`
	}
	switch mt {
	case types.OCIConfigJSON, types.DockerConfigJSON:
		return `https://github.com/opencontainers/image-spec/blob/master/config.md`
	case types.OCILayer, types.OCIUncompressedLayer, types.DockerLayer, types.DockerUncompressedLayer:
		return `https://github.com/opencontainers/image-spec/blob/master/layer.md`
	case types.OCIContentDescriptor:
		return `https://github.com/opencontainers/image-spec/blob/master/descriptor.md`
	case `application/vnd.dev.cosign.simplesigning.v1+json`:
		return `https://github.com/containers/image/blob/master/docs/containers-signature.5.md`
	}
	return `https://github.com/opencontainers/image-spec/blob/master/media-types.md`
}

var indexTmpl, manifestTmpl, descriptorTmpl, cosignTmpl *template.Template

func init() {
	indexTmpl = template.Must(template.New("indexTemplate").Funcs(fns).Parse(indexTemplate))
	manifestTmpl = template.Must(template.New("manifestTemplate").Funcs(fns).Parse(manifestTemplate))
	descriptorTmpl = template.Must(template.New("descriptorTemplate").Funcs(fns).Parse(descriptorTemplate))
	cosignTmpl = template.Must(template.New("cosignTemplate").Funcs(fns).Parse(cosignTemplate))
}

type IndexData struct {
	Repo       string
	CosignTag  string
	Reference  name.Reference
	Descriptor *remote.Descriptor
	v1.IndexManifest
}

type ManifestData struct {
	Repo       string
	Image      string
	CosignTag  string
	Reference  name.Reference
	Descriptor *remote.Descriptor
	v1.Manifest
}

type DescriptorData struct {
	Repo      string
	Reference name.Reference
	v1.Descriptor
}

type CosignData struct {
	Repo      string
	Reference name.Reference
	SimpleSigning
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
	if cosigns, ok := qs["cosign"]; ok {
		return renderCosign(w, cosigns[0])
	}
	if descs, ok := qs["descriptor"]; ok {
		return renderDescriptor(w, descs[0])
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

	cosign := false

	if _, ok := qs["discovery"]; ok {
		// TODO: Just pass this down.
		cosignRef, err := munge(ref.Context().Digest(desc.Digest.String()))
		if err != nil {
			return err
		}
		if _, err := remote.Head(cosignRef); err != nil {
			log.Printf("remote.Head(%q): %v", cosignRef.String(), err)
		} else {
			cosign = true
		}
	}

	if desc.MediaType == types.DockerManifestList || desc.MediaType == types.OCIImageIndex {
		return renderIndex(w, desc, ref, cosign)
	} else if desc.MediaType == types.DockerManifestSchema2 || desc.MediaType == types.OCIManifestSchema1 {
		return renderImage(w, desc, ref, cosign)
	}

	return fmt.Errorf("unimplemented mediaType: %s", desc.MediaType)
}

func munge(ref name.Reference) (name.Reference, error) {
	munged := strings.ReplaceAll(ref.String(), "@sha256:", "@sha256-")
	munged = strings.ReplaceAll(munged, "@", ":")
	munged = munged + ".cosign"
	return name.ParseReference(munged)
}

func renderIndex(w io.Writer, desc *remote.Descriptor, ref name.Reference, cosign bool) error {
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
		Reference:     ref,
		Descriptor:    desc,
		IndexManifest: *manifest,
	}

	if cosign {
		cr, err := munge(ref.Context().Digest(desc.Digest.String()))
		if err == nil {
			data.CosignTag = cr.Identifier()
		}
	}

	return indexTmpl.Execute(w, data)
}

func renderImage(w io.Writer, desc *remote.Descriptor, ref name.Reference, cosign bool) error {
	img, err := desc.Image()
	if err != nil {
		return err
	}

	manifest, err := img.Manifest()
	if err != nil {
		return err
	}

	data := ManifestData{
		Repo:       ref.Context().String(),
		Image:      ref.String(),
		Reference:  ref,
		Descriptor: desc,
		Manifest:   *manifest,
	}

	if cosign {
		cr, err := munge(ref.Context().Digest(desc.Digest.String()))
		if err == nil {
			data.CosignTag = cr.Identifier()
		}
	}

	return manifestTmpl.Execute(w, data)
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
	defer blob.Close()

	dec := json.NewDecoder(blob)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "   ")

	// TODO: Is there a way to just stream indentation without decoding?
	var m interface{}
	if err := dec.Decode(&m); err != nil {
		return err
	}

	return enc.Encode(m)
}

func renderDescriptor(w io.Writer, r string) error {
	ref, err := name.ParseReference(r, name.StrictValidation)
	if err != nil {
		return err
	}

	blob, err := remote.Blob(ref)
	if err != nil {
		return err
	}
	defer blob.Close()

	dec := json.NewDecoder(blob)

	var desc v1.Descriptor

	if err := dec.Decode(&desc); err != nil {
		return err
	}
	data := DescriptorData{
		Repo:       ref.Context().String(),
		Reference:  ref,
		Descriptor: desc,
	}

	return descriptorTmpl.Execute(w, data)
}

func renderCosign(w io.Writer, r string) error {
	ref, err := name.ParseReference(r, name.StrictValidation)
	if err != nil {
		return err
	}

	blob, err := remote.Blob(ref)
	if err != nil {
		return err
	}
	defer blob.Close()

	dec := json.NewDecoder(blob)

	var ss SimpleSigning

	if err := dec.Decode(&ss); err != nil {
		return err
	}

	// TODO: Remove me. Janky workaround for old artifacts.
	if !strings.HasPrefix(ss.Critical.Image.DockerManifestDigest, "sha256:") {
		ss.Critical.Image.DockerManifestDigest = "sha256:" + ss.Critical.Image.DockerManifestDigest
	}
	data := CosignData{
		Repo:          ref.Context().String(),
		Reference:     ref,
		SimpleSigning: ss,
	}

	return cosignTmpl.Execute(w, data)
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
	name = chunks[len(chunks)-1]
	log.Printf("Open(%q) (scrubbed)", name)
	for {
		header, err := fs.tr.Next()
		if err == io.EOF {
			log.Printf("Open(%q): EOF", name)
			break
		}
		if debug {
			log.Printf("Open(%q): header.Name = %q", name, header.Name)
		}
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
				if debug {
					log.Printf("name = %q, hdr.Linkname = %q, dir = %q", name, link, dir)
				}
				if !path.IsAbs(hdr.Linkname) {
					link = path.Clean(path.Join(path.Dir(name), link))
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

// Cosign simple signing stuff
type SimpleSigning struct {
	Critical Critical
	Optional map[string]string
}

type Critical struct {
	Identity Identity
	Image    Image
	Type     string
}

type Identity struct {
	DockerReference string `json:"docker-reference"`
}

type Image struct {
	DockerManifestDigest string `json:"Docker-manifest-digest"`
}
