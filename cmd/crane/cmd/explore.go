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
	"archive/tar"
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/internal/and"
	"github.com/google/go-containerregistry/internal/gzip"
	"github.com/google/go-containerregistry/internal/lexer"
	"github.com/google/go-containerregistry/internal/verify"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
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
		Use:   "explore IMAGE",
		Short: "Explore a registry or OCI layout via interactive tui",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return explore(args[0], *options)
		},
	}
}

func explore(src string, opts []crane.Option) error {
	options := crane.GetOptions(opts...)

	ref, err := name.ParseReference(src)
	if err != nil {
		return err
	}

	auth, err := options.Keychain.Resolve(ref.Context())
	if err != nil {
		return err
	}

	t := options.Transport
	t = transport.NewLogger(t)
	t = transport.NewRetry(t)
	t = transport.NewUserAgent(t, "")
	t, err = transport.New(ref.Context().Registry, auth, t, []string{ref.Scope(transport.PullScope)})
	if err != nil {
		return err
	}

	opts = append(opts, crane.WithTransport(t))
	options = crane.GetOptions(opts...)

	// TODO: HEAD for cache to avoid rate limit
	// d, err := remote.Head(ref, opts...)
	// if err != nil {
	// 	return err
	// }
	desc, err := remote.Get(ref, options.Remote...)
	if err != nil {
		return err
	}
	p := tea.NewProgram(initialModel(desc, ref, options), tea.WithAltScreen(), tea.WithMouseCellMotion())
	m, err := p.Run()
	if err != nil {
		return err
	}

	if m, ok := m.(*model); ok {
		fmt.Println(m.expr)
	}

	return nil
}

// links
type choice struct {
	ref   string
	mt    string
	size  int64
	text  string
	line  int
	query url.Values
}

type model struct {
	// oneof {
	b []byte
	f string
	// }

	ref     name.Reference
	mt      string
	options crane.Options
	w       *outputter
	expr    string

	cursor  int
	choices []choice
	choice  *choice

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
		expr:    "crane manifest " + ref.String(),
		ref:     ref,
		mt:      string(desc.MediaType),
		choices: []choice{},
		options: options,
	}
	return m
}

func (m *model) Init() tea.Cmd {
	return nil
}

func (m *model) update(msg tea.Msg) (tea.Model, error) {
	// TODO: errorful version
	return nil, nil
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if m.f != "" {
				defer os.Remove(m.f)
			}
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
				m.zoomin = false
			} else if m.offset > 0 {
				m.offset--
				m.zoomin = true
			}
		case "down", "j":
			if m.cursor < len(m.choices)-1 {
				m.cursor++
				m.zoomin = false
			} else if m.offset < len(m.lines)-m.height {
				m.offset++
				m.zoomin = true
			}
		case "ctrl+b":
			m.zoomin = true
			if m.offset > 0 {
				m.offset = max(0, m.offset-m.height)
			}
		case "ctrl+f":
			m.zoomin = true
			if m.offset < len(m.lines)-m.height {
				m.offset = min(m.offset+m.height, len(m.lines)-m.height)
			}
		case "enter", " ":
			// todo: pull this out of here
			if len(m.choices) == 0 {
				return m, nil
			}
			c := m.choices[m.cursor]
			mt := types.MediaType(c.mt)
			var err error
			var b []byte
			var fname string
			var expr string
			if mt.IsIndex() || mt.IsImage() || isSchema1(mt) {
				ref, err := name.ParseReference(c.ref)
				if err != nil {
					panic(err)
				}
				desc, err := remote.Get(ref, m.options.Remote...)
				if err != nil {
					panic(err)
				}
				b = desc.Manifest
				if c.query != nil {
					b, expr, err = jq(c.ref, b, c.query)
					if err != nil {
						panic(err)
					}
				} else {
					expr = "crane manifest " + ref.String()
				}
			} else {
				expr = "crane blob " + c.ref

				var rc io.ReadCloser
				if c.mt == "url" {
					chunks := strings.SplitN(c.ref, "@", 2)
					if len(chunks) != 2 {
						panic(fmt.Errorf("weird url: %s", c.ref))
					}
					u := chunks[0]
					digest := chunks[1]
					resp, err := http.Get(u)
					if err != nil {
						panic(err)
					}
					if resp.StatusCode == http.StatusOK {
						expr = "curl -L " + u
						h, err := v1.NewHash(digest)
						if err != nil {
							panic(err)
						}
						rc, err = verify.ReadCloser(resp.Body, resp.ContentLength, h)
						if err != nil {
							panic(err)
						}
						defer rc.Close()
					}
				} else {
					blobRef, err := name.NewDigest(c.ref)
					if err != nil {
						panic(err)
					}
					l, err := remote.Layer(blobRef, m.options.Remote...)
					if err != nil {
						panic(err)
					}
					rc, err = l.Compressed()
					if err != nil {
						panic(err)
					}
					defer rc.Close()
				}

				if c.mt == "application/json" || strings.HasSuffix(c.mt, "+json") {
					b, err = io.ReadAll(rc)
					if err != nil {
						panic(err)
					}
				} else {
					f, err := os.CreateTemp("", "")
					if err != nil {
						panic(err)
					}
					defer f.Close()
					if _, err := io.Copy(f, rc); err != nil {
						panic(err)
					}
					fname = f.Name()
				}
			}
			newM := &model{
				b:       b,
				f:       fname,
				expr:    expr,
				ref:     m.ref,
				mt:      c.mt,
				choice:  &c,
				choices: []choice{},
				options: m.options,
				back:    m,
				lines:   []string{},
				height:  m.height,
				width:   m.width,
			}

			if ref, err := name.ParseReference(c.ref); err == nil {
				newM.ref = ref
			}
			return newM, nil
		case "backspace":
			if m.f != "" {
				defer os.Remove(m.f)
			}
			if m.back != nil {
				return m.back, nil
			}

			if strings.HasPrefix(m.expr, "crane ls ") {
				// todo: catalog or gcrane
				return m, nil
			}

			ts, err := remote.List(m.ref.Context(), m.options.Remote...)
			if err != nil {
				panic(err)
			}

			v := &tags{
				Tags: ts,
				Name: m.ref.Context().RepositoryStr(),
			}
			b, err := json.Marshal(v)
			if err != nil {
				panic(err)
			}

			return &model{
				b:       b,
				expr:    "crane ls " + m.ref.Context().String(),
				ref:     m.ref,
				choices: []choice{},
				options: m.options,
				lines:   []string{},
				height:  m.height,
				width:   m.width,
			}, nil
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

	if m.f != "" {
		blob, err := os.Open(m.f)
		if err != nil {
			panic(err)
		}
		defer blob.Close()
		var rc io.ReadCloser = blob
		gzipped, pr, err := gzip.Peek(blob)
		if err != nil {
			panic(err)
		}

		rc = &and.ReadCloser{Reader: pr, CloseFunc: blob.Close}
		if gzipped {
			// gzip
			rc, err = gzip.UnzipReadCloser(rc)
			if err != nil {
				panic(err)
			}
		}
		ok, pr, err := tarPeek(rc)
		if ok {
			if gzipped {
				m.expr += " | tar -tzf -"
			} else {
				m.expr += " | tar -tf -"
			}
			tr := tar.NewReader(pr)
			// tar
			for {
				header, err := tr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					panic(err)
				}
				m.lines = append(m.lines, header.Name)
			}
		}
	} else {
		var w strings.Builder
		m.w = &outputter{
			w:       &w,
			cursor:  m.cursor,
			fresh:   []bool{},
			ref:     m.ref.String(),
			mt:      m.mt,
			repo:    m.ref.Context().String(),
			choices: []choice{},
		}
		if m.choice != nil {
			m.w.query = m.choice.query
		}
		if m.w.query.Get("render") == "raw" {
			m.lines = strings.Split(string(m.b), "\n")
		} else {
			if err := renderJSON(m.w, m.b); err != nil {
				panic(err)
			}
			m.choices = m.w.choices
			m.lines = strings.Split(w.String(), "\n")
		}
		if m.cursor < len(m.choices) {
			buffer := int(float32(m.height) * .25)
			c := m.choices[m.cursor]
			if c.line+buffer > m.offset+m.height {
				m.offset = min(len(m.lines)-m.height, c.line+buffer-m.height)
			} else if c.line-buffer < m.offset {
				m.offset = max(0, c.line-buffer)
			}
		}
	}

	// Todo: maybe do this streaming or at least write to tmp file
	// instead of keeping everything in memory
	return strings.Join(m.visibleLines(), "\n")
}

func jq(ref string, b []byte, qs url.Values) ([]byte, string, error) {
	jq, ok := qs["jq"]
	if !ok {
		return b, "", nil
	}

	var (
		err error
		exp string
	)

	exps := []string{"crane maniest " + ref}

	for _, j := range jq {
		b, exp, err = evalBytes(j, b)
		if err != nil {
			return nil, "", err
		}
		exps = append(exps, exp)
	}

	return b, strings.Join(exps, " | "), nil
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
	w     *strings.Builder
	query url.Values
	name  string
	repo  string
	ref   string
	mt    string
	pt    string

	fresh []bool
	jq    []string
	key   bool
	root  map[string]interface{}
	isMap bool

	choices []choice
	cursor  int
	line    int
}

func (w *outputter) BlueDoc(query url.Values, text string) (bool, error) {
	return w.Echo(w.ref, w.mt, 0, text, query)
}

func (w *outputter) URL(url, text string) (bool, error) {
	return w.Echo(url, "url", 0, text, nil)
}

func (w *outputter) Linkify(mt string, h v1.Hash, size int64) (bool, error) {
	return w.Echo(w.repo+"@"+h.String(), mt, size, h.String(), nil)
}

func (w *outputter) JSON(ref, text string) (bool, error) {
	return w.Echo(ref, "application/json", 0, text, nil)
}

func (w *outputter) LinkImage(ref, text string) (bool, error) {
	return w.Echo(ref, string(types.OCIImageIndex), 0, text, nil)
}

func (w *outputter) LinkRepo(ref, text string) (bool, error) {
	return w.Echo(ref, "repo", 0, text, nil)
}

func (w *outputter) Echo(ref, mt string, size int64, text string, query url.Values) (bool, error) {
	text = strings.Trim(strconv.Quote(text), `"`)
	w.tabf()
	rendered := text
	if len(w.choices) == w.cursor {
		rendered = underline.Render(text)
	}
	w.choices = append(w.choices, choice{ref, mt, 0, text, w.line, query})
	w.Print(`"` + rendered + `"`)
	w.unfresh()
	w.key = false
	return true, nil
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

func (w *outputter) Query() url.Values {
	raw := w.query.Encode()
	q, err := url.ParseQuery(raw)
	if err != nil {
		panic(err)
	}
	return q
}

func (w *outputter) addQuery(key, value string) url.Values {
	qs := w.Query()
	qs.Add(key, value)
	return qs
}

func (w *outputter) setQuery(key, value string) url.Values {
	qs := w.Query()
	qs.Set(key, value)
	return qs
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

		i, ok := o[k]
		if !ok {
			panic(k)
		}

		if ok, err := renderMapEntry(w, o, k, v, i, rawMap); err != nil {
			return err
		} else if ok {
			continue
		}

		if err := renderRaw(w, &v); err != nil {
			return err
		}
	}
	w.EndMap()
	w.jpop()

	return nil
}

func renderMapEntry(w *outputter, o map[string]interface{}, k string, v json.RawMessage, i interface{}, rawMap map[string]json.RawMessage) (bool, error) {
	switch k {
	case "annotations":
		anns, ok := i.(map[string]interface{})
		if !ok {
			return false, nil
		}
		if err := renderAnnotations(w, anns, &v); err != nil {
			return false, err
		}

		return true, nil
	case "digest":
		mt, ok := o["mediaType"]
		if !ok {
			return false, nil
		}
		s, ok := mt.(string)
		if !ok {
			return false, nil
		}

		h := v1.Hash{}
		if err := json.Unmarshal(v, &h); err != nil {
			log.Printf("Unmarshal digest %q: %v", string(v), err)
			return false, nil
		}

		size := int64(0)
		if sz, ok := o["size"]; ok {
			if i64, ok := sz.(int64); ok {
				size = i64
			} else if f64, ok := sz.(float64); ok {
				size = int64(f64)
			}
		}
		return w.Linkify(s, h, size)
	case "urls":
		digest, ok := rawMap["digest"]
		if !ok {
			return false, nil
		}

		h := v1.Hash{}
		if err := json.Unmarshal(digest, &h); err != nil {
			log.Printf("Unmarshal digest %q: %v", string(digest), err)
			return false, nil
		}

		// We got a digest, so we can link to some blob.
		urls, ok := i.([]interface{})
		if !ok {
			return false, nil
		}

		if len(urls) == 0 {
			w.Value([]byte("[]"))
			return true, nil
		}
		w.StartArray()
		for _, iface := range urls {
			if u, ok := iface.(string); ok {
				// TODO: size
				w.URL(u+"@"+h.String(), u)
			} else {
				// This wasn't a list of strings, render whatever we found.
				b, err := json.Marshal(iface)
				if err != nil {
					return false, err
				}
				raw := json.RawMessage(b)
				if err := renderRaw(w, &raw); err != nil {
					return false, err
				}
			}
		}
		w.EndArray()

		return true, nil
	case "Docker-reference", "docker-reference":
		s, ok := i.(string)
		if !ok {
			return false, nil
		}
		ref, err := name.ParseReference(s)
		if err != nil {
			log.Printf("Parse[%q](%q): %v", k, ref, err)
			return false, nil
		}

		return w.LinkImage(ref.String(), ref.String())
	case "Docker-manifest-digest", "docker-manifest-digest":
		h := v1.Hash{}
		if err := json.Unmarshal(v, &h); err != nil {
			log.Printf("Unmarshal digest %q: %v", string(v), err)
			return false, nil
		}
		return w.LinkImage(w.repo+"@"+h.String(), h.String())
	case "blobSum":
		h := v1.Hash{}
		if err := json.Unmarshal(v, &h); err != nil {
			log.Printf("Unmarshal digest %q: %v", string(v), err)
			return false, nil
		}
		return w.Linkify(string(types.DockerLayer), h, 0)
	case "payload":
		href, ok := i.(string)
		if !ok {
			return false, nil
		}
		pt, ok := o["payloadType"]
		if !ok {
			return false, nil
		}
		s, ok := pt.(string)
		if !ok {
			return false, nil
		}
		if !(s == "application/json" || strings.HasSuffix(s, "+json")) {
			return false, nil
		}
		qs := w.addQuery("jq", strings.Join(w.jq, ""))
		return w.BlueDoc(qs, href)
	case "referenceLocator":
		ps, ok := i.(string)
		if !ok {
			return false, nil
		}
		p, err := parsePurl(ps)
		if err != nil {
			// todo warnf
			return false, nil
		}
		ref, err := p.url(w.repo)
		if err != nil {
			// todo warnf
			return false, nil
		}
		return w.Echo(ref, p.qualifiers.Get("mediaType"), 0, ps, nil)
	case "body":
		if !inside(w.query, "dev.sigstore.cosign/bundle") {
			return false, nil
		}
		s, ok := i.(string)
		if !ok {
			return false, nil
		}
		jq := strings.Join(w.jq, "")
		if jq != ".Payload.body" {
			return false, nil
		}
		qs := w.Query()
		qs.Add("jq", jq)
		qs.Add("jq", "base64 -d")
		return w.BlueDoc(qs, s)
	case "content", "publicKey":
		if !inside(w.query, "dev.sigstore.cosign/bundle") {
			return false, nil
		}
		s, ok := i.(string)
		if !ok {
			return false, nil
		}
		if !((w.path(".spec.publicKey") && w.kindVer("intoto/0.0.1")) || (w.path(".spec.signature.publicKey.content") && w.kindVer("hashedrekord/0.0.1"))) {
			return false, nil
		}

		qs := w.Query()
		qs.Add("jq", strings.Join(w.jq, ""))
		qs.Add("jq", "base64 -d")
		qs.Set("render", "raw")
		return w.BlueDoc(qs, s)
	case "value":
		if !inside(w.query, "dev.sigstore.cosign/bundle") {
			return false, nil
		}
		alg, ok := o["algorithm"]
		if !ok {
			return false, nil
		}
		s, ok := alg.(string)
		if !ok {
			return false, nil
		}
		if s != "sha256" {
			return false, nil
		}
		d, ok := i.(string)
		if !ok {
			return false, nil
		}
		if !((w.path(".spec.content.hash.value") && w.kindVer("intoto/0.0.1")) || (w.path(".spec.data.hash.value") && w.kindVer("hashedrekord/0.0.1"))) {
			return false, nil
		}
		return w.JSON(w.repo+"@sha256:"+d, d)
	case "v1Compatibility":
		s, ok := i.(string)
		if !ok {
			return false, nil
		}
		if w.jth(-2) != ".history" {
			return false, nil
		}
		qs := w.addQuery("jq", strings.Join(w.jq, ""))
		return w.BlueDoc(qs, s)
	case "tags":
		tags, ok := i.([]interface{})
		if !ok {
			return false, nil
		}
		if len(tags) == 0 {
			w.Value([]byte("[]"))
			return true, nil
		}
		w.StartArray()
		for _, iface := range tags {
			if original, ok := iface.(string); ok {
				w.LinkImage(w.repo+":"+original, original)
			} else {
				// This wasn't a list of strings, render whatever we found.
				b, err := json.Marshal(iface)
				if err != nil {
					return false, err
				}
				raw := json.RawMessage(b)
				if err := renderRaw(w, &raw); err != nil {
					return false, err
				}
			}
		}
		w.EndArray()

		return true, nil
	case "next":
		s, ok := i.(string)
		if !ok {
			return false, nil
		}
		qs := w.setQuery("next", s)
		return w.BlueDoc(qs, s)
	// google tag list extensions
	case "tag":
		tags, ok := i.([]interface{})
		if !ok {
			return false, nil
		}
		if len(tags) == 0 {
			w.Value([]byte("[]"))
			return true, nil
		}
		w.StartArray()
		for _, iface := range tags {
			if original, ok := iface.(string); ok {
				if w.jth(-2) == ".manifest" {
					maybeHash := strings.TrimLeft(w.jth(-1), ".")
					h, err := v1.NewHash(maybeHash)
					if err == nil {
						w.LinkImage(w.repo+":"+original+"@"+h.String(), original)
					} else {
						log.Printf("maybeHash(%q): %v", maybeHash, err)
					}
				}
				w.LinkImage(w.repo, original)
			} else {
				// This wasn't a list of strings, render whatever we found.
				b, err := json.Marshal(iface)
				if err != nil {
					return false, err
				}
				raw := json.RawMessage(b)
				if err := renderRaw(w, &raw); err != nil {
					return false, err
				}
			}
		}
		w.EndArray()

		return true, nil
	case "repositories", "child":
		repos, ok := i.([]interface{})
		if !ok {
			return false, nil
		}
		if len(repos) == 0 {
			w.Value([]byte("[]"))
			return true, nil
		}
		w.StartArray()
		for _, iface := range repos {
			if original, ok := iface.(string); ok {
				w.LinkRepo(path.Join(w.repo, original), original)
			} else {
				// This wasn't a list of strings, render whatever we found.
				b, err := json.Marshal(iface)
				if err != nil {
					return false, err
				}
				raw := json.RawMessage(b)
				if err := renderRaw(w, &raw); err != nil {
					return false, err
				}
			}
		}
		w.EndArray()

		return true, nil
	case "manifest":
		m, ok := i.(map[string]interface{})
		if !ok {
			return false, nil
		}
		return renderManifest(w, m, &v)
	}

	return false, nil
}

func inside(qs url.Values, ann string) bool {
	for _, jq := range qs["jq"] {
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
				// if any of these values aren't strings, bail
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

		i, ok := o[k]
		if !ok {
			panic(k)
		}

		switch k {
		case "org.opencontainers.image.base.name":
			if s, ok := i.(string); ok {
				ref, err := name.ParseReference(s)
				if err != nil {
					log.Printf("Parse[%q](%q): %v", k, ref, err)
				} else {
					w.LinkImage(ref.String(), ref.String())

					// Don't fall through to renderRaw.
					continue
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

							continue
						}
					}
				}
			}
		case "dev.sigstore.cosign/bundle", "dev.sigstore.cosign/timestamp", "sh.brew.tab":
			if s, ok := i.(string); ok {
				if w.jth(-1) == ".annotations" {
					qs := w.addQuery("jq", strings.Join(w.jq, ""))
					w.BlueDoc(qs, s)

					continue
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
func renderManifest(w *outputter, o map[string]interface{}, raw *json.RawMessage) (bool, error) {
	rawMap := map[string]json.RawMessage{}
	if err := json.Unmarshal(*raw, &rawMap); err != nil {
		return false, err
	}
	// Handle empty maps as {}.
	if len(rawMap) == 0 {
		w.Value([]byte("{}"))
		return true, nil
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
			w.choices = append(w.choices, choice{ref, string(types.OCIImageIndex), 0, k, w.line, nil})
			w.Key(rendered)
		}

		if err := renderRaw(w, &v); err != nil {
			return false, err
		}
	}

	w.EndMap()
	w.jpop()

	return true, nil
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

const (
	magicGNU, versionGNU     = "ustar ", " \x00"
	magicUSTAR, versionUSTAR = "ustar\x00", "00"
)

func tarPeek(r io.Reader) (bool, gzip.PeekReader, error) {
	// Make sure it's more than 512
	pr := bufio.NewReaderSize(r, 1024)

	block, err := pr.Peek(512)
	if err != nil {
		// https://github.com/google/go-containerregistry/issues/367
		if err == io.EOF {
			return false, pr, nil
		}
		return false, pr, err
	}

	magic := string(block[257:][:6])
	isTar := magic == magicGNU || magic == magicUSTAR
	return isTar, pr, nil
}

func evalBytes(j string, b []byte) ([]byte, string, error) {
	quote := false // this is a hack, we should be lexing properly instead
	l := lexer.Lex(j, j)
	item := l.NextItem()

	// Test the first thing to see if it's expected to be JSON.
	var v interface{} = b
	if item.Typ == lexer.ItemAccessor || item.Typ == lexer.ItemIndex {
		if err := json.Unmarshal(json.RawMessage(b), &v); err != nil {
			return nil, "", fmt.Errorf("unmarshal: %w", err)
		}
	}

	for {
		if item.Typ == lexer.ItemEOF {
			break
		}
		switch item.Typ {
		case lexer.ItemError:
			return nil, "", fmt.Errorf("lexer.ItemError: %w", item.Val)
		case lexer.ItemAccessor:
			quote = true
			vv, ok := v.(map[string]interface{})
			if !ok {
				return nil, "", fmt.Errorf("eval: access %s", item.Val)
			}
			v = vv[item.Val]
		case lexer.ItemIndex:
			vv, ok := v.([]interface{})
			if !ok {
				return nil, "", fmt.Errorf("eval: index %s", item.Val)
			}
			idx, err := strconv.Atoi(item.Val)
			if err != nil {
				return nil, "", fmt.Errorf("atoi: %w", err)
			}
			v = vv[idx]
		case lexer.ItemSentinel:
			switch strings.TrimSpace(item.Val) {
			case "base64 -d":
				s, err := toString(v)
				if err != nil {
					return nil, "", err
				}

				v, err = base64.StdEncoding.DecodeString(s)
				if err != nil {
					return nil, "", fmt.Errorf("base64 -d: %w", err)
				}
			}
		}
		item = l.NextItem()
	}

	b, err := toBytes(v)
	if err != nil {
		return nil, "", err
	}

	if quote {
		j = "jq -r '" + j + "'"
	}

	return b, j, nil
}

func toString(v interface{}) (string, error) {
	switch vv := v.(type) {
	case string:
		return vv, nil
	case []byte:
		return string(vv), nil
	}
	return "", fmt.Errorf("cannot convert %T to string", v)
}

func toBytes(v interface{}) ([]byte, error) {
	switch vv := v.(type) {
	case string:
		return []byte(vv), nil
	case []byte:
		return vv, nil
	}
	return nil, fmt.Errorf("cannot convert %T to bytes", v)
}

func isSchema1(mt types.MediaType) bool {
	return mt == types.DockerManifestSchema1 || mt == types.DockerManifestSchema1Signed
}

type tags struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}
