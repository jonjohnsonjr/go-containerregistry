package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/google/go-containerregistry/pkg/v1/v1util"
)

const debug = true

const (
	CosignMediaType = `application/vnd.dev.cosign.simplesigning.v1+json`
	cosignPointee   = `application/vnd.dev.ggcr.magic/cosign-thing+json`
)

type Outputter interface {
	Key(string)
	Value([]byte)
	StartMap()
	EndMap()
	StartArray()
	EndArray()
	Doc(url string, mt types.MediaType)
	URL(handler string, path, original string, h v1.Hash)
	Linkify(handler string, h v1.Hash)
}

type simpleOutputter struct {
	w     io.Writer
	repo  string
	fresh []bool
	key   bool
}

func (w *simpleOutputter) Doc(url string, mt types.MediaType) {
	w.tabf()
	w.Printf(`"<a class="mt" href="%s">%s</a>"`, url, html.EscapeString(string(mt)))
	w.unfresh()
	w.key = false
}

func (w *simpleOutputter) URL(handler string, path, original string, digest v1.Hash) {
	w.tabf()
	w.Printf(`"<a href="%s%s@%s">%s</a>"`, handler, path, digest.String(), html.EscapeString(original))
	w.unfresh()
	w.key = false
}

func (w *simpleOutputter) Linkify(handler string, digest v1.Hash) {
	w.tabf()
	w.Printf(`"<a href="%s%s@%s">%s</a>"`, handler, w.repo, digest.String(), html.EscapeString(digest.String()))
	w.unfresh()
	w.key = false
}

func (w *simpleOutputter) Key(k string) {
	w.tabf()
	w.Printf("%q:", k)
	w.key = true
}

func (w *simpleOutputter) Value(b []byte) {
	w.tabf()
	w.Printf(string(b))
	w.unfresh()
	w.key = false
}

func (w *simpleOutputter) StartMap() {
	w.tabf()
	w.Printf("{")
	w.newline()
	w.push()
	w.key = false
}

func (w *simpleOutputter) EndMap() {
	if !w.Fresh() {
		w.undiv()
	}
	w.pop()
	w.newline()
	w.Printf(w.tabs() + "}")
	w.key = false
	w.unfresh()
}

func (w *simpleOutputter) StartArray() {
	w.tabf()
	w.Printf("[")
	w.newline()
	w.push()
	w.key = false
}

func (w *simpleOutputter) EndArray() {
	if !w.Fresh() {
		w.undiv()
	}
	w.pop()
	w.newline()
	w.Printf(w.tabs() + "]")
	w.key = false
	w.unfresh()
}

func (w *simpleOutputter) Printf(s string, arg ...interface{}) {
	fmt.Fprintf(w.w, s, arg...)
}

func (w *simpleOutputter) tabf() {
	if !w.key {
		if !w.Fresh() {
			w.Printf(",")
			w.undiv()
			w.newline()
		}
		w.div()
		//w.Printf(w.tabs())
	} else {
		w.Printf(" ")
	}
}

func (w *simpleOutputter) Fresh() bool {
	if len(w.fresh) == 0 {
		return true
	}
	return w.fresh[len(w.fresh)-1]
}

func (w *simpleOutputter) push() {
	w.Printf(w.tabs() + `<div class="indent">` + "\n")
	w.fresh = append(w.fresh, true)
}

func (w *simpleOutputter) pop() {
	w.fresh = w.fresh[:len(w.fresh)-1]
	w.newline()
	w.Printf(w.tabs())
	w.undiv()
}

func (w *simpleOutputter) tabs() string {
	return strings.Repeat("  ", len(w.fresh))
	//return ""
}

func (w *simpleOutputter) newline() {
	w.Printf("\n")
}

func (w *simpleOutputter) div() {
	w.Printf(w.tabs() + "<div>")
}

func (w *simpleOutputter) undiv() {
	w.Printf("</div>")
}

func (w *simpleOutputter) unfresh() {
	if len(w.fresh) == 0 {
		return
	}
	w.fresh[len(w.fresh)-1] = false
}

func (w *simpleOutputter) refresh() {
	w.fresh[len(w.fresh)-1] = true
}

// renderJSON formats some JSON bytes in an OCI-specific way.
//
// We try to convert maps to meaningful values based on a Descriptor:
// - mediaType: well-known links to their definitions.
// - digest: links to raw content or well-known handlers:
//		1. Well-known OCI types get rendered as renderJSON
//		2. Layers get rendered as a filesystem via http.FileSystem
//		3. Blobs ending in +json get rendered as formatted JSON
//		4. Cosign blobs (SimpleSigning) get rendered specially
//		5. Everything else is raw content
//
// If we see a map, try to parse as Descriptor and use those values.
//
// Anything else, recursively look for maps to try to parse as descriptors.
//
// Keep the rest of the RawMessage in tact.
//
// []byte -> json.RawMessage
// json.RawMessage -> map[string]json.RawMessage (v1.Desciptor?)
// json.RawMessage -> {map[string]raw, []raw, float64, string, bool, nil}
func renderJSON(w Outputter, b []byte) error {
	raw := json.RawMessage(b)
	return renderRaw(w, &raw)
}

func renderRaw(w Outputter, raw *json.RawMessage) error {
	var v interface{}
	if err := json.Unmarshal(*raw, &v); err != nil {
		return err
	}
	switch vv := v.(type) {
	case []interface{}:
		if err := renderList(w, raw); err != nil {
			return err
		}
	case map[string]interface{}:
		if err := renderMap(w, vv, raw); err != nil {
			return err
		}
	default:
		b, err := raw.MarshalJSON()
		if err != nil {
			return err
		}
		safeBuf := bytes.Buffer{}
		json.HTMLEscape(&safeBuf, b)
		w.Value(safeBuf.Bytes())
	}
	return nil
}

// Make sure we see things in this order.
var precedence = []string{"schemaVersion", "mediaType", "config", "layers", "manifests", "size", "digest", "platform", "urls", "annotations"}
var ociMap map[string]int

func init() {
	ociMap = map[string]int{}
	for i, s := range precedence {
		ociMap[s] = i
	}
}

func compare(a, b string) bool {
	i, ok := ociMap[a]
	j, kk := ociMap[b]

	// Inter-OCI comparison.
	if ok && kk {
		return i < j
	}

	// Straight string comparison.
	if !ok && !kk {
		return a < b
	}

	// If ok == true,  a = OCI, b = string
	// If ok == false, a = string, b = OCI
	return ok
}

func renderMap(w Outputter, o map[string]interface{}, raw *json.RawMessage) error {
	rawMap := map[string]json.RawMessage{}
	if err := json.Unmarshal(*raw, &rawMap); err != nil {
		return err
	}

	w.StartMap()

	// Make this a stable order.
	keys := make([]string, 0, len(rawMap))
	for k := range rawMap {
		keys = append(keys, k)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		return compare(keys[i], keys[j])
	})

	for _, k := range keys {
		v := rawMap[k]
		w.Key(k)

		switch k {
		case "digest":
			if mt, ok := o["mediaType"]; ok {
				if s, ok := mt.(string); ok {
					h := v1.Hash{}
					if err := json.Unmarshal(v, &h); err != nil {
						log.Printf("Unmarshal digest %q: %v", string(v), err)
					} else {
						w.Linkify("/"+handlerForMT(s), h)

						// Don't fall through to renderRaw.
						continue
					}
				}
			}
		case "mediaType":
			mt := ""
			if err := json.Unmarshal(v, &mt); err != nil {
				log.Printf("Unmarshal mediaType %q: %v", string(v), err)
			} else {
				w.Doc(getLink(mt), types.MediaType(mt))

				// Don't fall through to renderRaw.
				continue
			}
		case "urls":
			if digest, ok := rawMap["digest"]; ok {
				h := v1.Hash{}
				if err := json.Unmarshal(digest, &h); err != nil {
					log.Printf("Unmarshal digest %q: %v", string(digest), err)
				} else {
					// We got a digest, so we can link to some blob.
					if urls, ok := o["urls"]; ok {
						if ii, ok := urls.([]interface{}); ok {
							log.Printf("urls is []interface{}")
							w.StartArray()
							for _, iface := range ii {
								if original, ok := iface.(string); ok {
									scheme := "https"
									u := original
									if strings.HasPrefix(original, "https://") {
										u = strings.TrimPrefix(original, "https://")
									} else if strings.HasPrefix(original, "http://") {
										u = strings.TrimPrefix(original, "http://")
										scheme = "http"
									}
									// Chrome redirection breaks without this, possibly because it interprets:
									// "sha256:abcd" as a hostname?
									if !strings.HasSuffix(u, "/") {
										u = u + "/"
									}
									w.URL("/"+scheme+"/", u, original, h)
								} else {
									// This wasn't a list of strings, render whatever we found.
									b, err := json.Marshal(iface)
									if err != nil {
										return err
									}
									raw := json.RawMessage(b)
									if err := renderRaw(w, &raw); err != nil {
										return err
									}
								}
							}
							w.EndArray()
						}
					}
				}
			}
			// Don't fall through to renderRaw.
			continue

		case "Docker-manifest-digest":
			h := v1.Hash{}
			if err := json.Unmarshal(v, &h); err != nil {
				log.Printf("Unmarshal digest %q: %v", string(v), err)
			} else {
				// TODO: This could maybe be better but we don't have a MT.
				w.Linkify("/"+handlerForMT(cosignPointee), h)

				// Don't fall through to renderRaw.
				continue
			}
		}

		if err := renderRaw(w, &v); err != nil {
			return err
		}
	}
	w.EndMap()

	return nil
}

func renderList(w Outputter, raw *json.RawMessage) error {
	rawList := []json.RawMessage{}
	if err := json.Unmarshal(*raw, &rawList); err != nil {
		return err
	}
	w.StartArray()
	for _, v := range rawList {
		if err := renderRaw(w, &v); err != nil {
			return err
		}
	}
	w.EndArray()

	return nil
}

const landingPage = `
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
<h2>explore.<a class="mt" href="https://github.com/google/go-containerregistry">ggcr</a>.dev</h2>
<p>
This janky tool allows you to <em>explore</em> the contents of a registry interactively.
</p>
<p>
Enter a <strong>public</strong> image, e.g. <tt>"ubuntu"</tt>:
</p>
<form action="/" method="GET">
<input type="text" name="image" value="ubuntu"/>
<input type="submit" />
</form>
</body>
</html>
`

const header = `
<html>
<head>
<style>
.mt:hover {
	text-decoration: underline;
}
	
.mt {
  color: inherit;
	text-decoration: inherit; 
}

body {
	font-family: monospace;
}

.indent {
  margin-left: 2em;
}
</style>
</head>
`

const bodyTemplate = `
<body>
<div>
<h2>{{.Reference}}{{ if .CosignTag }} (<a href="?image={{.Repo}}:{{.CosignTag}}">cosign</a>){{end}}</h2>
Docker-Content-Digest: {{.Descriptor.Digest}}<br>
Content-Length: {{.Descriptor.Size}}<br>
Content-Type: {{.Descriptor.MediaType}}<br>
</div>
<hr>
`
const footer = `
</body>
</html>
`

func handlerForMT(s string) string {
	mt := types.MediaType(s)
	if !mt.IsDistributable() {
		// TODO?
		return `fs/`
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
	case cosignPointee:
		return `?discovery=true&image=`
	case CosignMediaType:
		return `?cosign=`
	}
	if strings.HasSuffix(s, "+json") {
		return `?config=`
	}

	// TODO: raw?
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

var bodyTmpl *template.Template

func init() {
	bodyTmpl = template.Must(template.New("bodyTemplate").Parse(bodyTemplate))
}

type HeaderData struct {
	Repo       string
	Image      string
	CosignTag  string
	Reference  name.Reference
	Descriptor *remote.Descriptor
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
	http.HandleFunc("/http/", fsHandler)
	http.HandleFunc("/https/", fsHandler)
	http.HandleFunc("/gzip/", fsHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}

func renderLanding(w http.ResponseWriter) error {
	_, err := io.Copy(w, strings.NewReader(landingPage))
	return err
}

func getBlob(r *http.Request) (string, bool) {
	qs := r.URL.Query()
	if q, ok := qs["config"]; ok {
		return q[0], ok
	}
	if q, ok := qs["cosign"]; ok {
		return q[0], ok
	}
	if q, ok := qs["descriptor"]; ok {
		return q[0], ok
	}

	return "", false
}

func munge(ref name.Reference) (name.Reference, error) {
	munged := strings.ReplaceAll(ref.String(), "@sha256:", "@sha256-")
	munged = strings.ReplaceAll(munged, "@", ":")
	munged = munged + ".cosign"
	return name.ParseReference(munged)
}

func renderResponse(w http.ResponseWriter, r *http.Request) error {
	qs := r.URL.Query()

	if images, ok := qs["image"]; ok {
		return renderManifest(w, r, images[0])
	}
	if blob, ok := getBlob(r); ok {
		return renderBlobJSON(w, blob)
	}

	return renderLanding(w)
}

func renderManifest(w http.ResponseWriter, r *http.Request, image string) error {
	qs := r.URL.Query()

	ref, err := name.ParseReference(image, name.WeakValidation)
	if err != nil {
		return err
	}
	desc, err := remote.Get(ref)
	if err != nil {
		return err
	}

	data := HeaderData{
		Repo:       ref.Context().String(),
		Image:      ref.String(),
		Reference:  ref,
		Descriptor: desc,
	}

	if _, ok := qs["discovery"]; ok {
		cosignRef, err := munge(ref.Context().Digest(desc.Digest.String()))
		if err != nil {
			return err
		}
		if _, err := remote.Head(cosignRef); err != nil {
			log.Printf("remote.Head(%q): %v", cosignRef.String(), err)
		} else {
			data.CosignTag = cosignRef.Identifier()
		}
	}

	fmt.Fprintf(w, header)

	if err := bodyTmpl.Execute(w, data); err != nil {
		return err
	}
	output := &simpleOutputter{
		w:     w,
		fresh: []bool{},
		repo:  ref.Context().String(),
	}
	if err := renderJSON(output, desc.Manifest); err != nil {
		return err
	}
	// TODO: This is janky.
	output.undiv()

	fmt.Fprintf(w, footer)

	return nil
}

func renderBlobJSON(w http.ResponseWriter, blobRef string) error {
	ref, err := name.ParseReference(blobRef, name.StrictValidation)
	if err != nil {
		return err
	}

	blob, err := remote.Blob(ref)
	if err != nil {
		return err
	}
	defer blob.Close()

	fmt.Fprintf(w, header)

	output := &simpleOutputter{
		w:     w,
		fresh: []bool{},
		repo:  ref.Context().String(),
	}

	// TODO: I need blob.Stat with a limit and a hard-coded size limit.
	// TODO: Can we do this in a streaming way?
	b, err := ioutil.ReadAll(blob)
	if err != nil {
		return err
	}
	if err := renderJSON(output, b); err != nil {
		return err
	}
	// TODO: This is janky.
	output.undiv()

	fmt.Fprintf(w, footer)

	return nil
}

func fetchBlob(r *http.Request) (io.ReadCloser, string, error) {
	path, root, err := splitFsURL(r.URL.Path)
	if err != nil {
		return nil, "", err
	}

	chunks := strings.Split(path, "@")
	if len(chunks) != 2 {
		return nil, "", fmt.Errorf("not enough chunks: %s", path)
	}
	// 71 = len("sha256:") + 64
	if len(chunks[1]) < 71 {
		return nil, "", fmt.Errorf("second chunk too short: %s", chunks[1])
	}

	ref := strings.Join([]string{chunks[0], chunks[1][:71]}, "@")
	if ref == "" {
		return nil, "", fmt.Errorf("bad ref: %s", path)
	}

	if root == "/http/" || root == "/https/" {
		log.Printf("chunks[0]: %v", chunks[0])

		u := chunks[0]

		scheme := "https://"
		if root == "/http/" {
			scheme = "http://"
		}
		u = scheme + u
		log.Printf("GET %v", u)

		// TODO: wrap in digest verification?
		resp, err := http.Get(u)
		if err != nil {
			return nil, "", err
		}
		if resp.StatusCode == http.StatusOK {
			return resp.Body, root + ref, nil
		}
		resp.Body.Close()
		log.Printf("GET %s failed: %s", u, resp.Status)
	}

	blobRef, err := name.ParseReference(ref, name.StrictValidation)
	if err != nil {
		return nil, "", err
	}

	rc, err := remote.Blob(blobRef)
	return rc, root + ref, err
}

func fsHandler(w http.ResponseWriter, r *http.Request) {
	if err := renderBlob(w, r); err != nil {
		fmt.Fprintf(w, "failed: %v", err)
	}
}

func splitFsURL(p string) (string, string, error) {
	for _, prefix := range []string{"/fs/", "/https/", "/http/", "/gzip/"} {
		if strings.HasPrefix(p, prefix) {
			return strings.TrimPrefix(p, prefix), prefix, nil
		}
	}

	return "", "", fmt.Errorf("unexpected path: %v", p)
}

func renderBlob(w http.ResponseWriter, r *http.Request) error {
	log.Printf("%v", r.URL)

	blob, ref, err := fetchBlob(r)
	if err != nil {
		return err
	}
	zr, err := v1util.GunzipReadCloser(blob)
	if err != nil {
		return err
	}
	defer zr.Close()

	log.Printf("ref: %v", ref)

	// Bit of a hack for tekton bundles...
	if strings.HasPrefix(ref, "/gzip/") {
		_, err := io.Copy(w, zr)
		return err
	}

	fs := &layerFs{
		ref: ref,
		tr:  tar.NewReader(zr),
	}

	http.FileServer(fs).ServeHTTP(w, r)

	return nil
}

type layerFs struct {
	ref     string
	url     string
	tr      *tar.Reader
	headers []*tar.Header
}

func (fs *layerFs) Open(name string) (http.File, error) {
	log.Printf("Open(%q)", name)
	name = strings.TrimPrefix(name, fs.ref)
	chunks := strings.Split(name, " -> ")
	name = chunks[len(chunks)-1]
	log.Printf("Open(%q) (scrubbed)", name)
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
			log.Printf("Open(%q): header.Name = %q", name, header.Name)
		}
		fs.headers = append(fs.headers, header)
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

				// For symlinks, assume relative. Hardlinks seem absolute?
				if hdr.Typeflag == tar.TypeSymlink {
					if !path.IsAbs(hdr.Linkname) {
						link = path.Clean(path.Join(path.Dir(name), link))
					}
					if debug {
						log.Printf("symlink: %v -> %v", hdr.Linkname, link)
					}
				}

				if hdr.Typeflag == tar.TypeLink {
					link = path.Clean("/" + link)

					if debug {
						log.Printf("hardlink: %v -> %v", hdr.Linkname, link)
					}
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
		if debug {
			log.Printf("Stat(%q): root!", f.name)
		}
		return fileInfo{f.name}, nil
	}
	if debug {
		log.Printf("Stat(%q): nonroot!", f.name)
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
	return time.Now()
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
