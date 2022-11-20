// Copyright 2022 Google LLC All Rights Reserved.
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

package cmd

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/spf13/cobra"

	// TODO: drop these?
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var underline = lipgloss.NewStyle().Underline(true)

// NewCmdExplore creates a new cobra.Command for the explore subcommand.
func NewCmdExplore(options *[]crane.Option) *cobra.Command {
	return &cobra.Command{
		Use:     "explore SRC DST",
		Aliases: []string{"cp"},
		Short:   "Explore a registry or OCI layout via interactive tui",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			options := crane.GetOptions(*options...)
			return explore(args[0], options)
		},
	}
}

func explore(src string, options crane.Options) error {
	ref, err := name.ParseReference(src)
	if err != nil {
		return err
	}
	// TODO: HEAD for cache to avoid rate limit
	// TODO: Reuse transport to avoid reauth
	// d, err := remote.Head(ref, opts...)
	// if err != nil {
	// 	return err
	// }
	desc, err := remote.Get(ref, options.Remote...)
	if err != nil {
		return err
	}
	p := tea.NewProgram(initialModel(desc, ref, options), tea.WithAltScreen(), tea.WithMouseCellMotion())
	if _, err := p.Run(); err != nil {
		return err
	}

	return nil
}

// links
type choice struct {
	ref  string
	mt   string
	size int64
	text string
	line int
}

type model struct {
	b       []byte
	ref     name.Reference
	options crane.Options
	w       *outputter

	cursor  int
	choices []choice

	// to avoid reloading everything on backspace
	back *model

	lines []string

	// window size
	height int
	width  int

	// vertical lines offset from 0
	offset int

	// allow j/k to go past first and last links
	zoomin bool
}

func initialModel(desc *remote.Descriptor, ref name.Reference, options crane.Options) *model {
	m := &model{
		b:       desc.Manifest,
		ref:     ref,
		choices: []choice{},
		options: options,
	}
	return m
}

func (m *model) Init() tea.Cmd {
	return nil
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			} else if m.offset > 0 {
				m.offset--
				m.zoomin = false
			}
		case "down", "j":
			if m.cursor < len(m.choices)-1 {
				m.cursor++
				m.zoomin = false
			} else if m.offset < len(m.lines)-m.height {
				m.offset++
				m.zoomin = true
			}
		case "enter", " ":
			// todo: pull this out of here
			c := m.choices[m.cursor]
			ref, err := name.ParseReference(c.ref)
			if err != nil {
				panic(err)
			}
			mt := types.MediaType(c.mt)
			var b []byte
			if mt.IsIndex() || mt.IsImage() {
				desc, err := remote.Get(ref, m.options.Remote...)
				if err != nil {
					panic(err)
				}
				b = desc.Manifest
			} else if strings.HasSuffix(c.mt, "+json") {
				blobRef, err := name.NewDigest(c.ref)
				if err != nil {
					panic(err)
				}

				l, err := remote.Layer(blobRef, m.options.Remote...)
				if err != nil {
					panic(err)
				}
				rc, err := l.Compressed()
				if err != nil {
					panic(err)
				}
				defer rc.Close()
				b, err = io.ReadAll(rc)
				if err != nil {
					panic(err)
				}
			} else {
				// todo: return a model that renders filesystems
			}
			newM := &model{
				b:       b,
				ref:     ref,
				choices: []choice{},
				options: m.options,
				back:    m,
				lines:   []string{},
				height:  m.height,
				width:   m.width,
			}
			return newM, nil
		case "backspace":
			if m.back != nil {
				return m.back, nil
			}
		}
	case tea.WindowSizeMsg:
		m.height = msg.Height
		m.width = msg.Width
	}

	return m, nil
}

func (m *model) View() string {
	if m.zoomin {
		// we don't have to re-render cuz we're just scrolling
		return strings.Join(m.visibleLines(), "\n")
	}
	var w strings.Builder
	m.w = &outputter{
		w:       &w,
		cursor:  m.cursor,
		fresh:   []bool{},
		repo:    m.ref.Context().String(),
		choices: []choice{},
	}
	if err := renderJSON(m.w, m.b); err != nil {
		panic(err)
	}
	m.choices = m.w.choices
	m.lines = strings.Split(w.String(), "\n")
	if m.cursor < len(m.choices) {
		buffer := int(float32(m.height) * .25)
		c := m.choices[m.cursor]
		if c.line+buffer > m.offset+m.height {
			m.offset = min(len(m.lines)-m.height, c.line+buffer-m.height)
		} else if c.line-buffer < m.offset {
			m.offset = max(0, c.line-buffer)
		}
	}

	// Todo: maybe do this streaming or at least write to tmp file
	// instead of keeping everything in memory
	return strings.Join(m.visibleLines(), "\n")
}

// cribbed from bubbletea viewport
func (m *model) visibleLines() (lines []string) {
	if len(m.lines) > 0 {
		top := max(0, m.offset)
		bottom := clamp(m.offset+m.height, top, len(m.lines))
		lines = m.lines[top:bottom]
	}
	return lines
}

func clamp(v, low, high int) int {
	if high < low {
		low, high = high, low
	}
	return min(high, max(low, v))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// TODO: this was hastily adapted from http handler stuff, rewrite the whole
// thing to be a lot simpler
type outputter struct {
	w    *strings.Builder
	u    *url.URL
	name string
	repo string
	mt   string
	pt   string

	fresh []bool
	jq    []string
	key   bool
	root  map[string]interface{}
	isMap bool

	choices []choice
	cursor  int
	line    int
}

// TODO: Lots of stuff used this in explore.ggcr.dev that we need to recreate
// (mostly the jq stuff, but also repo pagination)
func (w *outputter) BlueDoc(url, text string) {
	w.tabf()
	w.Printf(`"<a href="%s">%s</a>"`, url, html.EscapeString(strings.Trim(strconv.Quote(text), `"`)))
	w.unfresh()
	w.key = false
}

func (w *outputter) URL(url, text string) {
	w.Echo(url, "url", 0, text)
}

func (w *outputter) Linkify(mt string, h v1.Hash, size int64) {
	w.Echo(w.repo+"@"+h.String(), mt, size, h.String())
}

func (w *outputter) Blob(ref, text string) {
	w.Echo(ref, "application/json", 0, text)
}

func (w *outputter) LinkImage(ref, text string) {
	w.Echo(ref, string(types.OCIImageIndex), 0, text)
}

// TODO: have a way to query for repos
func (w *outputter) LinkRepo(ref, text string) {
	w.Echo(ref, "repo", 0, text)
}

func (w *outputter) Echo(ref, mt string, size int64, text string) {
	w.tabf()
	rendered := text
	if len(w.choices) == w.cursor {
		rendered = underline.Render(text)
	}
	w.choices = append(w.choices, choice{ref, mt, 0, text, w.line})
	w.Print(rendered)
	w.unfresh()
	w.key = false
}

func (w *outputter) Key(k string) {
	w.tabf()
	w.Printf(`"%s":`, k)
	w.key = true
}

func (w *outputter) Value(b []byte) {
	w.tabf()
	w.Print(string(b))
	w.unfresh()
	w.key = false
}

func (w *outputter) StartMap() {
	w.tabf()
	w.Print("{")
	w.newline()
	w.push()
	w.key = false
}

func (w *outputter) EndMap() {
	if !w.Fresh() {
		w.undiv()
	}
	w.pop()
	w.newline()
	w.Print(w.tabs() + "}")
	w.key = false
	w.name = ""
	w.unfresh()
}

func (w *outputter) StartArray() {
	w.tabf()
	w.Print("[")
	w.newline()
	w.push()
	w.key = false
}

func (w *outputter) EndArray() {
	if !w.Fresh() {
		w.undiv()
	}
	w.pop()
	w.newline()
	w.Print(w.tabs() + "]")
	w.key = false
	w.unfresh()
}

func (w *outputter) Printf(s string, arg ...interface{}) {
	fmt.Fprintf(w.w, s, arg...)
}

func (w *outputter) Print(s string) {
	fmt.Fprint(w.w, s)
}

func (w *outputter) tabf() {
	if !w.key {
		if !w.Fresh() {
			w.Print(",")
			w.undiv()
			w.newline()
		}
		w.div()
		w.Printf(w.tabs())
	} else {
		w.Print(" ")
	}
}

func (w *outputter) Fresh() bool {
	if len(w.fresh) == 0 {
		return true
	}
	return w.fresh[len(w.fresh)-1]
}

func (w *outputter) push() {
	w.fresh = append(w.fresh, true)
}

func (w *outputter) pop() {
	w.fresh = w.fresh[:len(w.fresh)-1]
	w.undiv()
}

func (w *outputter) jpush(j string) {
	w.jq = append(w.jq, j)
}

func (w *outputter) jpop() {
	w.jq = w.jq[:len(w.jq)-1]
}

func (w *outputter) jth(idx int) string {
	if len(w.jq)+idx-1 < 0 {
		return ""
	}
	if len(w.jq)+idx-1 > len(w.jq)-1 {
		return ""
	}

	s := w.jq[len(w.jq)+idx-1]
	return s
}

func (w *outputter) path(s string) bool {
	return strings.Join(w.jq, "") == s
}

func (w *outputter) kindVer(s string) bool {
	return w.maybeMap("kind")+"/"+w.maybeMap("apiVersion") == s
}

func (w *outputter) maybeMap(k string) string {
	if w.root == nil {
		return ""
	}
	v, ok := w.root[k]
	if !ok {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func (w *outputter) tabs() string {
	return strings.Repeat("  ", len(w.fresh))
	//return ""
}

func (w *outputter) newline() {
	w.line++
	w.Print("\n")
}

func (w *outputter) div() {
}

func (w *outputter) undiv() {
}

func (w *outputter) unfresh() {
	if len(w.fresh) == 0 {
		return
	}
	w.fresh[len(w.fresh)-1] = false
}

func (w *outputter) refresh() {
	w.fresh[len(w.fresh)-1] = true
}

// todo: rewrite this stuff to not roundtrip through urls
func (w *outputter) addQuery(key, value string) url.URL {
	u := *w.u
	qs := u.Query()
	qs.Add(key, value)
	u.RawQuery = qs.Encode()
	return u
}

func (w *outputter) setQuery(key, value string) url.URL {
	u := *w.u
	qs := u.Query()
	qs.Set(key, value)
	u.RawQuery = qs.Encode()
	return u
}

// renderJSON formats some JSON bytes in an OCI-specific way.
//
// We try to convert maps to meaningful values based on a Descriptor:
// - mediaType: well-known links to their definitions.
// - digest: links to raw content or well-known handlers:
//  1. Well-known OCI types get rendered as renderJSON
//  2. Layers get rendered as a filesystem via http.FileSystem
//  3. Blobs ending in +json get rendered as formatted JSON
//  4. Everything else is raw content
//
// If we see a map, try to parse as Descriptor and use those values.
//
// Anything else, recursively look for maps to try to parse as descriptors.
//
// Keep the rest of the RawMessage in tact.
//
// []byte -> json.RawMessage
// json.RawMessage -> {map[string]raw, []raw, float64, string, bool, nil}
func renderJSON(w *outputter, b []byte) error {
	raw := json.RawMessage(b)

	// Unmarshal an extra time at the beginning to check if it's a map for easy
	// access to root fields. This is dumb but I'm lazy.
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	if m, ok := v.(map[string]interface{}); ok {
		w.root = m
	}

	if err := renderRaw(w, &raw); err != nil {
		return fmt.Errorf("renderRaw: %w", err)
	}
	w.undiv()
	return nil
}

func renderRaw(w *outputter, raw *json.RawMessage) error {
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

func renderList(w *outputter, raw *json.RawMessage) error {
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
	for index, v := range rawList {
		w.jpush(fmt.Sprintf("[%d]", index))
		if err := renderRaw(w, &v); err != nil {
			return err
		}
		w.jpop()
	}
	w.EndArray()

	return nil
}

// Make sure we see things in this order.
var precedence = []string{
	"schemaVersion",
	"mediaType",
	"config",
	"layers",
	"manifests",
	"size",
	"name",
	"digest",
	"platform",
	"urls",
	"annotations",
	"_type",
	"predicateType",
	"subject",
	"predicate",
}
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

func renderMap(w *outputter, o map[string]interface{}, raw *json.RawMessage) error {
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

	for idx, k := range keys {
		if idx != 0 {
			// Handle continues.
			w.jpop()
		}

		v := rawMap[k]
		w.Key(k)
		if strings.Contains(k, ".") {
			w.jpush(fmt.Sprintf("[%q]", k))
		} else {
			w.jpush("." + k)
		}

		switch k {
		case "annotations":
			var i interface{}
			if err := json.Unmarshal(v, &i); err != nil {
				return err
			}
			if vv, ok := i.(map[string]interface{}); ok {
				if err := renderAnnotations(w, vv, &v); err != nil {
					return err
				}

				// Don't fall through to renderRaw.
				continue
			}
		case "digest":
			if mt, ok := o["mediaType"]; ok {
				if s, ok := mt.(string); ok {
					h := v1.Hash{}
					if err := json.Unmarshal(v, &h); err != nil {
						log.Printf("Unmarshal digest %q: %v", string(v), err)
					} else {
						size := int64(0)
						if sz, ok := o["size"]; ok {
							if i64, ok := sz.(int64); ok {
								size = i64
							} else if f64, ok := sz.(float64); ok {
								size = int64(f64)
							}
						}
						w.Linkify(s, h, size)

						// Don't fall through to renderRaw.
						continue
					}
				}
			}
			if w.pt == "application/vnd.in-toto+json" {
				if name, ok := o["name"]; ok {
					if ns, ok := name.(string); ok {
						w.name = ns // cleared by EndMap
					}
				}
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
							if len(ii) == 0 {
								w.Value([]byte("[]"))
								continue
							}
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
									// TODO: size
									w.URL("/"+scheme+"/"+url.PathEscape(u)+"@"+h.String(), original)
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

							// Don't fall through to renderRaw.
							continue
						}
					}
				}
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
		case "payload":
			if js, ok := o[k]; ok {
				if href, ok := js.(string); ok {
					if pt, ok := o["payloadType"]; ok {
						if s, ok := pt.(string); ok {
							u := w.addQuery("payloadType", s)
							w.BlueDoc(u.String(), href)

							// Don't fall through to renderRaw.
							continue
						}
					}
				}
			}
		case "referenceLocator":
			if js, ok := o[k]; ok {
				if ps, ok := js.(string); ok {
					p, err := parsePurl(ps)
					if err == nil {
						ref, err := p.url(w.repo)
						if err == nil {
							w.Echo(ref, p.qualifiers.Get("mediaType"), 0, ps)
							// Don't fall through to renderRaw.
							continue
						}
					}
				}
			}
		case "body":
			if inside(w.u, "dev.sigstore.cosign/bundle") {
				if js, ok := o[k]; ok {
					if s, ok := js.(string); ok {
						jq := strings.Join(w.jq, "")
						if jq == ".Payload.body" {
							u := *w.u
							qs := u.Query()
							qs.Add("jq", jq)
							qs.Add("jq", "base64 -d")
							u.RawQuery = qs.Encode()
							w.BlueDoc(u.String(), s)

							continue
						}
					}
				}
			}
		case "content", "publicKey":
			if inside(w.u, "dev.sigstore.cosign/bundle") {
				if js, ok := o[k]; ok {
					if s, ok := js.(string); ok {
						if (w.path(".spec.publicKey") && w.kindVer("intoto/0.0.1")) || (w.path(".spec.signature.publicKey.content") && w.kindVer("hashedrekord/0.0.1")) {
							u := *w.u
							qs := u.Query()
							qs.Add("jq", strings.Join(w.jq, ""))
							qs.Add("jq", "base64 -d")
							qs.Set("render", "raw")
							u.RawQuery = qs.Encode()
							w.BlueDoc(u.String(), s)

							continue
						}
					}
				}
			}
		case "value":
			if inside(w.u, "dev.sigstore.cosign/bundle") {
				if (w.path(".spec.content.hash.value") && w.kindVer("intoto/0.0.1")) || (w.path(".spec.data.hash.value") && w.kindVer("hashedrekord/0.0.1")) {
					if i, ok := o["algorithm"]; ok {
						if s, ok := i.(string); ok {
							if s == "sha256" {
								if js, ok := o[k]; ok {
									if d, ok := js.(string); ok {
										w.Blob(w.repo+"@sha256:"+d, d)
										continue
									}
								}
							}
						}
					}
				}
			}
		case "v1Compatibility":
			if js, ok := o[k]; ok {
				if s, ok := js.(string); ok {
					if w.jth(-2) == ".history" {
						u := w.addQuery("jq", strings.Join(w.jq, ""))
						w.BlueDoc(u.String(), s)

						continue
					}
				}
			}
		case "tags":
			if mv, ok := o[k]; ok {
				if ii, ok := mv.([]interface{}); ok {
					if len(ii) == 0 {
						w.Value([]byte("[]"))
						continue
					}
					w.StartArray()
					for _, iface := range ii {
						if original, ok := iface.(string); ok {
							w.LinkImage(w.repo+":"+original, original)
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

					// Don't fall through to renderRaw.
					continue
				}
			}
		case "next":
			if js, ok := o[k]; ok {
				if s, ok := js.(string); ok {
					u := w.setQuery("next", s)
					w.BlueDoc(u.String(), s)

					// Don't fall through to renderRaw.
					continue
				}
			}
		// google tag list extensions
		case "tag":
			if mv, ok := o[k]; ok {
				if ii, ok := mv.([]interface{}); ok {
					if len(ii) == 0 {
						w.Value([]byte("[]"))
						continue
					}
					w.StartArray()
					for _, iface := range ii {
						if original, ok := iface.(string); ok {
							if w.jth(-2) == ".manifest" {
								maybeHash := strings.TrimLeft(w.jth(-1), ".")
								h, err := v1.NewHash(maybeHash)
								if err == nil {
									w.LinkImage(w.repo+":"+original+"@"+h.String(), original)
									continue
								} else {
									log.Printf("maybeHash(%q): %v", maybeHash, err)
								}
							}
							w.LinkImage(w.repo, original)
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

					// Don't fall through to renderRaw.
					continue
				}
			}
		case "repositories", "child":
			if mv, ok := o[k]; ok {
				if ii, ok := mv.([]interface{}); ok {
					if len(ii) == 0 {
						w.Value([]byte("[]"))
						continue
					}
					w.StartArray()
					for _, iface := range ii {
						if original, ok := iface.(string); ok {
							w.LinkRepo(path.Join(w.repo, original), original)
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

					// Don't fall through to renderRaw.
					continue
				}
			}
		case "manifest":
			var i interface{}
			if err := json.Unmarshal(v, &i); err != nil {
				return err
			}
			if vv, ok := i.(map[string]interface{}); ok {
				if err := renderManifest(w, vv, &v); err != nil {
					return err
				}

				// Don't fall through to renderRaw.
				continue
			}
		}

		if err := renderRaw(w, &v); err != nil {
			return err
		}
	}
	w.EndMap()
	w.jpop()

	return nil
}

func inside(u *url.URL, ann string) bool {
	for _, jq := range u.Query()["jq"] {
		if strings.Contains(jq, `.annotations["`+ann+`"]`) {
			return true
		}
	}
	return false
}

// todo: refactor
func renderAnnotations(w *outputter, o map[string]interface{}, raw *json.RawMessage) error {
	rawMap := map[string]json.RawMessage{}
	if err := json.Unmarshal(*raw, &rawMap); err != nil {
		return err
	}
	// Handle empty maps as {}.
	if len(rawMap) == 0 {
		w.Value([]byte("{}"))
		return nil
	}

	// Make this a stable order.
	keys := make([]string, 0, len(rawMap))
	for k := range rawMap {
		keys = append(keys, k)
		if v, ok := o[k]; ok {
			if _, ok := v.(string); !ok {
				return renderRaw(w, raw)
			}
		}
	}
	sort.SliceStable(keys, func(i, j int) bool {
		return compare(keys[i], keys[j])
	})

	w.StartMap()

	for idx, k := range keys {
		if idx != 0 {
			// Handle continues.
			w.jpop()
		}

		v := rawMap[k]
		w.Key(k)

		if strings.Contains(k, ".") {
			w.jpush(fmt.Sprintf("[%q]", k))
		} else {
			w.jpush("." + k)
		}

		switch k {
		case "org.opencontainers.image.base.name":
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
		case "org.opencontainers.image.base.digest":
			h := v1.Hash{}
			if err := json.Unmarshal(v, &h); err != nil {
				log.Printf("Unmarshal digest %q: %v", string(v), err)
			} else {
				if js, ok := o["org.opencontainers.image.base.name"]; ok {
					if s, ok := js.(string); ok {
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
		case "dev.sigstore.cosign/bundle", "dev.sigstore.cosign/timestamp", "sh.brew.tab":
			if js, ok := o[k]; ok {
				if s, ok := js.(string); ok {
					if w.jth(-1) == ".annotations" {
						u := w.addQuery("jq", strings.Join(w.jq, ""))
						w.BlueDoc(u.String(), s)

						continue
					}
				}
			}
		case "org.opencontainers.image.documentation", "org.opencontainers.image.source", "org.opencontainers.image.url":
			if js, ok := o[k]; ok {
				if href, ok := js.(string); ok {
					if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
						w.BlueDoc(href, href)

						// Don't fall through to renderRaw.
						continue
					}
				}
			}
		}

		if err := renderRaw(w, &v); err != nil {
			return err
		}
	}

	w.EndMap()
	w.jpop()

	return nil
}

// todo: refactor
func renderManifest(w *outputter, o map[string]interface{}, raw *json.RawMessage) error {
	rawMap := map[string]json.RawMessage{}
	if err := json.Unmarshal(*raw, &rawMap); err != nil {
		return err
	}
	// Handle empty maps as {}.
	if len(rawMap) == 0 {
		w.Value([]byte("{}"))
		return nil
	}

	// Make this a stable order.
	keys := make([]string, 0, len(rawMap))
	for k := range rawMap {
		keys = append(keys, k)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		return compare(keys[i], keys[j])
	})

	w.StartMap()

	for idx, k := range keys {
		if idx != 0 {
			// Handle continues.
			w.jpop()
		}

		if strings.Contains(k, ".") {
			w.jpush(fmt.Sprintf("[%q]", k))
		} else {
			w.jpush("." + k)
		}

		v := rawMap[k]
		h, err := v1.NewHash(k)
		if err != nil {
			log.Printf("Unmarshal digest %q: %v", k, err)
			w.Key(k)
		} else {
			ref := w.repo + "@" + h.String()
			rendered := k
			if len(w.choices) == w.cursor {
				rendered = underline.Render(k)
			}
			w.choices = append(w.choices, choice{ref, string(types.OCIImageIndex), 0, k, w.line})
			w.Key(rendered)
		}

		if err := renderRaw(w, &v); err != nil {
			return err
		}
	}

	w.EndMap()
	w.jpop()

	return nil
}

type purl struct {
	tipe       string // type is a keyword lol
	namespace  string
	name       string
	version    string
	qualifiers url.Values
	subpath    string
}

func (p *purl) url(repo string) (string, error) {
	switch p.tipe {
	case "oci":
		if p.version == "" {
			return "", fmt.Errorf("no version in purl")
		}
		repository := p.qualifiers.Get("repository_url")
		if repository != "" {
			if p.namespace != "" {
				repository = path.Join(repository, p.namespace, p.name)
			} else {
				repository = path.Join(repository, p.name)
			}
		} else {
			repository = repo
		}
		delim := "@"
		if !strings.Contains(p.version, ":") {
			delim = ":"
		}
		return repository + delim + p.version, nil
	}

	return "", fmt.Errorf("nope")
}

// scheme:type/namespace/name@version?qualifiers#subpath
func parsePurl(s string) (*purl, error) {
	if !strings.HasPrefix(s, "pkg:") {
		return nil, fmt.Errorf("does not start with 'pkg:': %s", s)
	}

	p := &purl{}
	s = strings.TrimPrefix(s, "pkg:")
	chunks := strings.SplitN(s, "/", 2)
	if len(chunks) != 2 {
		return nil, fmt.Errorf("weird purl: %s", s)
	}

	p.tipe = chunks[0]
	s = chunks[1]

	chunks = strings.SplitN(s, "/", 2)
	if len(chunks) == 2 {
		p.namespace = chunks[0]
		s = chunks[1]
	}

	// Optional stuff...
	version := false
	qualifiers := false

	chunks = strings.SplitN(s, "@", 2)
	if len(chunks) == 2 {
		p.name = chunks[0]
		s = chunks[1]
		version = true
	}

	chunks = strings.SplitN(s, "?", 2)
	if len(chunks) == 2 {
		if version {
			p.version = chunks[0]
		} else {
			p.name = chunks[0]
		}
		s = chunks[1]
		qualifiers = true
		version = false
	}

	chunks = strings.Split(s, "#")
	if len(chunks) == 2 {
		p.subpath = chunks[1]
	}

	if qualifiers {
		q, err := url.ParseQuery(chunks[0])
		if err != nil {
			return nil, err
		}
		p.qualifiers = q
	} else if version {
		p.version = chunks[0]
	} else {
		p.name = chunks[0]
	}

	return p, nil
}
