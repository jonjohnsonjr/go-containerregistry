// Copyright 2021 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package explore

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

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
	Linkify(mt string, h v1.Hash, size int64)
	LinkImage(ref, text string)
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
	w.Printf(`"<a href="%s%s@%s/">%s</a>"`, handler, url.PathEscape(path), digest.String(), html.EscapeString(original))
	w.unfresh()
	w.key = false
}

func (w *simpleOutputter) Linkify(mt string, digest v1.Hash, size int64) {
	w.tabf()
	qs := "?"
	handler := handlerForMT(mt)
	if strings.Contains(handler, "?") {
		qs = "&"
	}
	if size != 0 {
		w.Printf(`"<a href="/%s%s@%s%smt=%s&size=%d">%s</a>"`, handler, w.repo, digest.String(), qs, mt, size, html.EscapeString(digest.String()))
	}
	w.Printf(`"<a href="/%s%s@%s%smt=%s">%s</a>"`, handler, w.repo, digest.String(), qs, mt, html.EscapeString(digest.String()))
	w.unfresh()
	w.key = false
}

func (w *simpleOutputter) LinkImage(ref, text string) {
	w.tabf()
	w.Printf(`"<a href="/?image=%s">%s</a>"`, url.PathEscape(ref), html.EscapeString(text))
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
	w.Printf(html.EscapeString(string(b)))
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
		return renderList(w, raw)
	case map[string]interface{}:
		return renderMap(w, vv, raw)
	case string:
		vs := v.(string)
		w.Value([]byte(strconv.Quote(vs)))
		return nil
	default:
		b, err := raw.MarshalJSON()
		if err != nil {
			return err
		}
		w.Value(b)
		return nil
	}
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

	// Handle empty maps as {}.
	if len(rawMap) == 0 {
		w.Value([]byte("{}"))
		return nil
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
						size := int64(0)
						if sz, ok := o["size"]; ok {
							if sz, ok := sz.(int64); ok {
								size = sz
							}
						}
						w.Linkify(s, h, size)

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

		case "Docker-reference", "docker-reference", "org.opencontainers.image.base.name":
			if js, ok := o[k]; ok {
				if s, ok := js.(string); ok {
					ref, err := name.ParseReference(s)
					if err != nil {
						log.Printf("Parse[%q](%q): %v", k, ref, err)
					} else {
						w.LinkImage(ref.String(), ref.String())

						// Don't fall through to renderRaw.
						continue
					}
				}
			}

		case "Docker-manifest-digest", "docker-manifest-digest":
			h := v1.Hash{}
			if err := json.Unmarshal(v, &h); err != nil {
				log.Printf("Unmarshal digest %q: %v", string(v), err)
			} else {
				// TODO: This could maybe be better but we don't have a MT.
				w.Linkify(cosignPointee, h, 0)

				// Don't fall through to renderRaw.
				continue
			}
		case "blobSum":
			h := v1.Hash{}
			if err := json.Unmarshal(v, &h); err != nil {
				log.Printf("Unmarshal digest %q: %v", string(v), err)
			} else {
				w.Linkify(string(types.DockerLayer), h, 0)

				// Don't fall through to renderRaw.
				continue
			}
		case "org.opencontainers.image.base.digest":
			h := v1.Hash{}
			if err := json.Unmarshal(v, &h); err != nil {
				log.Printf("Unmarshal digest %q: %v", string(v), err)
			} else {
				if mt, ok := o["org.opencontainers.image.base.name"]; ok {
					if s, ok := mt.(string); ok {
						base, err := name.ParseReference(s)
						if err != nil {
							log.Printf("Parse[%q](%q): %v", k, base, err)
						} else {
							w.LinkImage(base.Context().Digest(h.String()).String(), h.String())

							// Don't fall through to renderRaw.
							continue
						}
					}
				}
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

	// Handle empty lists as [].
	if len(rawList) == 0 {
		w.Value([]byte("[]"))
		return nil
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

func handlerForMT(s string) string {
	mt := types.MediaType(s)
	if !mt.IsDistributable() {
		return `fs/`
	}
	if mt.IsImage() {
		return `?image=`
	}
	if mt.IsIndex() {
		return `?image=`
	}
	switch mt {
	case types.OCILayer, types.OCIUncompressedLayer, types.DockerLayer, types.DockerUncompressedLayer:
		return `fs/`
	case types.OCIContentDescriptor, CosignMediaType, types.OCIConfigJSON, types.DockerConfigJSON:
		return `json/`
	case cosignPointee:
		return `?discovery=true&image=`
	case types.DockerManifestSchema1, types.DockerManifestSchema1Signed:
		return `?image=`
	}
	if strings.HasSuffix(s, "+json") {
		return `json/`
	}

	return `blob/`
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
