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
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/internal/httpserve"
	"github.com/google/go-containerregistry/internal/soci"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
)

// We should not buffer blobs greater than 2MB
const tooBig = 1 << 21
const respTooBig = 1 << 25
const ua = "explore.ggcr.dev (jonjohnson at google dot com, if this is breaking you)"

type handler struct {
	mux    *http.ServeMux
	remote []remote.Option

	// digest -> remote.desc
	manifests map[string]*remote.Descriptor

	// reg.String() -> ping resp
	pings map[string]*transport.PingResp

	tocCache   cache
	indexCache cache

	sync.Mutex
	sawTags map[string][]string

	oauth *oauth2.Config
}

type Option func(h *handler)

func WithRemote(opt []remote.Option) Option {
	return func(h *handler) {
		h.remote = opt
	}
}

func New(opts ...Option) http.Handler {
	h := handler{
		mux:        http.NewServeMux(),
		manifests:  map[string]*remote.Descriptor{},
		pings:      map[string]*transport.PingResp{},
		sawTags:    map[string][]string{},
		tocCache:   buildTocCache(),
		indexCache: buildIndexCache(),
		oauth:      buildOauth(),
	}

	for _, opt := range opts {
		opt(&h)
	}

	h.mux.HandleFunc("/", h.errHandler(h.renderResponse))

	h.mux.HandleFunc("/fs/", h.errHandler(h.renderFS))

	// Janky workaround for downloading via the "urls" field.
	h.mux.HandleFunc("/http/", h.errHandler(h.renderFS))
	h.mux.HandleFunc("/https/", h.errHandler(h.renderFS))

	h.mux.HandleFunc("/layers/", h.errHandler(h.renderLayers))
	h.mux.HandleFunc("/cache/", h.errHandler(h.renderIndex))

	// Try to detect mediaType.
	h.mux.HandleFunc("/blob/", h.errHandler(h.renderFS))

	h.mux.HandleFunc("/oauth", h.oauthHandler)

	return &h
}

func splitFsURL(p string) (string, string, error) {
	for _, prefix := range []string{"/fs/", "/layers/", "/https/", "/http/", "/blob/", "/cache/"} {
		if strings.HasPrefix(p, prefix) {
			return strings.TrimPrefix(p, prefix), prefix, nil
		}
	}

	return "", "", fmt.Errorf("unexpected path: %v", p)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.oauth == nil {
		// Cloud run already logs this stuff, don't log extra.
		log.Printf("%v", r.URL)

		start := time.Now()
		defer func() {
			log.Printf("%v (%s)", r.URL, time.Since(start))
		}()
	}

	if r.URL.Path == "/favicon.svg" || r.URL.Path == "/favicon.ico" {
		w.Header().Set("Cache-Control", "max-age=3600")
		http.ServeFile(w, r, filepath.Join(os.Getenv("KO_DATA_PATH"), "favicon.svg"))
		return
	}
	if r.URL.Path == "/robots.txt" {
		w.Header().Set("Cache-Control", "max-age=3600")
		http.ServeFile(w, r, filepath.Join(os.Getenv("KO_DATA_PATH"), "robots.txt"))
		return
	}

	h.mux.ServeHTTP(w, r)
}

type HandleFuncE func(http.ResponseWriter, *http.Request) error

func (h *handler) errHandler(hfe HandleFuncE) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := hfe(w, r); err != nil {
			if err := h.maybeOauthErr(w, r, err); err != nil {
				log.Printf("%s: %v", r.URL.Path, err)
				fmt.Fprintf(w, "failed: %s", html.EscapeString(err.Error()))
			}
		}
	}
}

func (h *handler) renderResponse(w http.ResponseWriter, r *http.Request) error {
	qs := r.URL.Query()

	if image := qs.Get("image"); image != "" {
		return h.renderManifest(w, r, image)
	}
	if blob := qs.Get("blob"); blob != "" {
		return h.renderBlobJSON(w, r, blob)
	}
	if repo := qs.Get("repo"); repo != "" {
		return h.renderRepo(w, r, repo)
	}

	// Cache landing page for 5 minutes.
	w.Header().Set("Cache-Control", "max-age=300")
	w.Write([]byte(landingPage))

	return nil
}

// Render repo with tags linking to images.
func (h *handler) renderRepo(w http.ResponseWriter, r *http.Request, repo string) error {
	ref, err := name.NewRepository(repo)
	if err != nil {
		return err
	}

	reg := ref.RegistryStr()
	googleRepo := reg == "registry.k8s.io" || reg == "mirror.gcr.io" || (isGoogle(reg) && ref.RepositoryStr() != "")
	hubRepo := strings.HasPrefix(repo, "index.docker.io") || strings.HasPrefix(repo, "docker.io") && strings.Count(repo, "/") == 1

	if googleRepo {
		return h.renderGoogleRepo(w, r, repo)
	}
	if ref.RepositoryStr() == "" {
		return h.renderCatalog(w, r, repo)
	}
	if hubRepo {
		return h.renderDockerHub(w, r, repo)
	}

	if err := headerTmpl.Execute(w, TitleData{repo}); err != nil {
		return err
	}
	header := HeaderData{
		Repo:      repo,
		Reference: repo,
		JQ:        crane("ls") + " " + repo,
	}
	if strings.Contains(repo, "/") || (ref.RegistryStr() == name.DefaultRegistry || ref.RegistryStr() == "docker.io") {
		fullRepo := path.Join(ref.RegistryStr(), ref.RepositoryStr())
		base := path.Base(fullRepo)
		dir := path.Dir(strings.TrimRight(fullRepo, "/"))
		if base != "." && dir != "." {
			if strings.HasPrefix(dir, "index.docker.io") {
				dir = strings.Replace(dir, "index.docker.io", "docker.io", 1)
			}
			header.Up = &RepoParent{
				Parent:    dir,
				Child:     base,
				Separator: "/",
			}
		}
	}
	if err := bodyTmpl.Execute(w, header); err != nil {
		return err
	}

	output := &jsonOutputter{
		w:     w,
		u:     r.URL,
		fresh: []bool{},
		repo:  repo,
	}

	tags, err := h.listTags(w, r, ref, repo)
	if err != nil {
		if tags == nil {
			return err
		}

		// Sometimes we time out (or other issues), render whatever we got.
		fmt.Fprintf(w, "<p>returning partial response, saw error: %s</p>\n<hr>\n", err)
	}

	b, err := json.Marshal(tags)
	if err != nil {
		return err
	}
	if err := renderJSON(output, b); err != nil {
		return err
	}

	fmt.Fprintf(w, footer)
	return nil
}

func (h *handler) renderGoogleRepo(w http.ResponseWriter, r *http.Request, repo string) error {
	ref, err := name.NewRepository(repo)
	if err != nil {
		return err
	}
	tags, err := google.List(ref, h.googleOptions(w, r, repo)...)
	if err != nil {
		return err
	}
	h.Lock()
	h.sawTags[ref.String()] = tags.Tags
	h.Unlock()
	if err := headerTmpl.Execute(w, TitleData{repo}); err != nil {
		return err
	}
	header := HeaderData{
		Repo:      repo,
		Reference: repo,
		JQ:        gcrane + " ls --json " + repo + " | jq .",
	}
	if ref.RepositoryStr() == "" {
		uri := &url.URL{
			Scheme: ref.Registry.Scheme(),
			Host:   ref.Registry.RegistryStr(),
			Path:   "/v2/tags/list",
		}
		header.JQ = fmt.Sprintf("curl -sL %q | jq .", uri.String())
	}
	if strings.Contains(repo, "/") {
		base := path.Base(repo)
		dir := path.Dir(strings.TrimRight(repo, "/"))
		if base != "." && dir != "." {
			header.Up = &RepoParent{
				Parent:    dir,
				Child:     base,
				Separator: "/",
			}
		}
	}
	if err := bodyTmpl.Execute(w, header); err != nil {
		return err
	}

	output := &jsonOutputter{
		w:     w,
		u:     r.URL,
		fresh: []bool{},
		repo:  repo,
	}
	b, err := json.Marshal(tags)
	if err != nil {
		return err
	}
	if err := renderJSON(output, b); err != nil {
		return err
	}

	fmt.Fprintf(w, footer)
	return nil
}

// https://hub.docker.com/v2/repositories/tonistiigi/?page_size=25&page=1&ordering=last_updated
func (h *handler) renderDockerHub(w http.ResponseWriter, r *http.Request, repo string) error {
	t := remote.DefaultTransport
	t = transport.NewRetry(t)
	t = transport.NewUserAgent(t, ua)
	if r.URL.Query().Get("trace") != "" {
		t = transport.NewTracer(t)
	}
	t = transport.Wrap(t)

	if err := headerTmpl.Execute(w, TitleData{repo}); err != nil {
		return err
	}
	uri := &url.URL{
		Scheme:   "https",
		Host:     "hub.docker.com",
		Path:     fmt.Sprintf("/v2/repositories/%s/", path.Base(repo)),
		RawQuery: "page_size=25&ordering=last_updated",
	}
	nextUri := uri.String()
	if next := r.URL.Query().Get("next"); next != "" {
		if strings.HasPrefix(next, "https://hub.docker.com/v2/repositories") {
			nextUri = next
		}
	}

	header := HeaderData{
		Repo:      repo,
		Reference: repo,
		JQ:        fmt.Sprintf("curl -sL %q | jq .", nextUri),
	}

	if strings.Contains(repo, "/") {
		base := path.Base(repo)
		dir := path.Dir(strings.TrimRight(repo, "/"))
		if base != "." && dir != "." {
			header.Up = &RepoParent{
				Parent:    dir,
				Child:     base,
				Separator: "/",
			}
		}
	}
	if err := bodyTmpl.Execute(w, header); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, nextUri, nil)
	if err != nil {
		return err
	}
	resp, err := t.RoundTrip(req)
	if err != nil {
		return err
	}

	b, err := io.ReadAll(io.LimitReader(resp.Body, tooBig))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	output := &jsonOutputter{
		w:         w,
		u:         r.URL,
		fresh:     []bool{},
		repo:      repo,
		dockerHub: true,
	}
	if err := renderJSON(output, b); err != nil {
		return err
	}

	fmt.Fprintf(w, footer)
	return nil
}

func (h *handler) renderCatalog(w http.ResponseWriter, r *http.Request, repo string) error {
	ref, err := name.NewRepository(repo)
	if err != nil {
		return err
	}
	if err := headerTmpl.Execute(w, TitleData{repo}); err != nil {
		return err
	}
	header := HeaderData{
		Repo:      repo,
		Reference: repo,
		JQ:        crane("catalog") + " " + repo,
	}
	if err := bodyTmpl.Execute(w, header); err != nil {
		return err
	}

	output := &jsonOutputter{
		w:     w,
		u:     r.URL,
		fresh: []bool{},
		repo:  repo,
	}

	v, err := h.listCatalog(w, r, ref, repo)
	if err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := renderJSON(output, b); err != nil {
		return err
	}

	fmt.Fprintf(w, footer)
	return nil
}

// Render manifests with links to blobs, manifests, etc.
func (h *handler) renderManifest(w http.ResponseWriter, r *http.Request, image string) error {
	ref, err := name.ParseReference(image, name.WeakValidation)
	if err != nil {
		return err
	}

	desc, err := h.fetchManifest(w, r, ref)
	if err != nil {
		return fmt.Errorf("fetchManifest: %w", err)
	}

	header := h.manifestHeader(ref, desc.Descriptor)

	u := *r.URL
	if _, ok := ref.(name.Digest); ok {
		// Allow this to be cached for an hour.
		w.Header().Set("Cache-Control", "max-age=3600, immutable")
	} else {
		// Rewrite links to include digest (not tag) for better caching.
		newImage := image + "@" + desc.Digest.String()
		qs := u.Query()
		qs.Set("image", newImage)
		u.RawQuery = qs.Encode()
	}

	if err := headerTmpl.Execute(w, TitleData{image}); err != nil {
		return fmt.Errorf("headerTmpl: %w", err)
	}

	output := &jsonOutputter{
		w:     w,
		u:     &u,
		fresh: []bool{},
		repo:  ref.Context().String(),
		mt:    string(desc.MediaType),
	}

	// Mutates header for bodyTmpl.
	b, err := h.jq(output, desc.Manifest, r, header)
	if err != nil {
		return fmt.Errorf("h.jq: %w", err)
	}

	if r.URL.Query().Get("render") == "x509" {
		if bytes.Count(b, []byte("-----BEGIN CERTIFICATE-----")) > 1 {
			header.JQ += " | while openssl x509 -text -noout 2>/dev/null; do :; done"
		} else {
			header.JQ += " | openssl x509 -text -noout"
		}
	} else if r.URL.Query().Get("render") == "history" {
		header.JQ = strings.TrimSuffix(header.JQ, " | jq .")
		header.JQ += ` | jq '.history[] | .v1Compatibility' -r | jq '.container_config.Cmd | join(" ")' -r | tac`
	}

	if err := bodyTmpl.Execute(w, header); err != nil {
		return fmt.Errorf("bodyTmpl: %w", err)
	}

	if err := h.renderContent(w, r, ref, b, output, u); err != nil {
		return err
	}

	fmt.Fprintf(w, footer)

	return nil
}

// Render blob as JSON, possibly containing refs to images.
func (h *handler) renderBlobJSON(w http.ResponseWriter, r *http.Request, blobRef string) error {
	ref, err := name.NewDigest(blobRef)
	if err != nil {
		return fmt.Errorf("NewDigest: %w", err)
	}

	opts := h.remoteOptions(w, r, ref.Context().Name())
	opts = append(opts, remote.WithMaxSize(tooBig))

	l, err := remote.Layer(ref, opts...)
	if err != nil {
		return fmt.Errorf("remote.Layer: %w", err)
	}
	blob, err := l.Compressed()
	if err != nil {
		return fmt.Errorf("Compressed: %w", err)
	}
	defer blob.Close()

	size, err := l.Size()
	if err != nil {
		log.Printf("layer %s Size(): %v", ref, err)
		return fmt.Errorf("cannot check blob size: %w", err)
	} else if size > tooBig {
		return fmt.Errorf("blob %s too big: %d > %d", ref, size, tooBig)
	}

	// Allow this to be cached for an hour.
	w.Header().Set("Cache-Control", "max-age=3600, immutable")

	if err := headerTmpl.Execute(w, TitleData{blobRef}); err != nil {
		return fmt.Errorf("headerTmpl: %w", err)
	}

	digest := ref.Identifier()
	hash, err := v1.NewHash(digest)
	if err != nil {
		return fmt.Errorf("NewHash: %w", err)
	}

	output := &jsonOutputter{
		w:     w,
		u:     r.URL,
		fresh: []bool{},
		repo:  ref.Context().String(),
		mt:    r.URL.Query().Get("mt"),
	}

	mediaType := types.MediaType("application/octet-stream")
	if output.mt != "" {
		mediaType = types.MediaType(output.mt)
	}

	desc := v1.Descriptor{
		Size:      size,
		Digest:    hash,
		MediaType: mediaType,
	}
	header := headerData(ref, desc)
	header.Up = &RepoParent{
		Parent:    ref.Context().String(),
		Separator: "@",
		Child:     ref.Identifier(),
	}
	header.JQ = crane("blob") + " " + ref.String()

	// TODO: Can we do this in a streaming way?
	input, err := ioutil.ReadAll(io.LimitReader(blob, tooBig))
	if err != nil {
		return err
	}

	// Mutates header for bodyTmpl.
	b, err := h.jq(output, input, r, header)
	if err != nil {
		return fmt.Errorf("h.jq: %w", err)
	}

	if r.URL.Query().Get("render") == "history" {
		header.JQ = strings.TrimSuffix(header.JQ, " | jq .")
		header.JQ += " | jq '.history[] | .created_by' -r"

	} else if r.URL.Query().Get("render") == "der" {
		header.JQ += " | openssl x509 -inform der -text -noout"
	}

	if err := bodyTmpl.Execute(w, header); err != nil {
		return fmt.Errorf("bodyTmpl: %w", err)
	}

	if err := h.renderContent(w, r, ref, b, output, *r.URL); err != nil {
		return fmt.Errorf("renderContent: %w", err)
	}

	fmt.Fprintf(w, footer)

	return nil
}

func (h *handler) renderContent(w http.ResponseWriter, r *http.Request, ref name.Reference, b []byte, output *jsonOutputter, u url.URL) error {
	switch r.URL.Query().Get("render") {
	case "raw":
		fmt.Fprintf(w, "<pre>")
		if _, err := w.Write(b); err != nil {
			return err
		}
		fmt.Fprintf(w, "</pre>")
	case "x509":
		return renderx509(w, b)
	case "cert":
		return renderCert(w, b, u)
	case "der":
		return renderDer(w, b)
	case "history":
		if types.MediaType(r.URL.Query().Get("mt")).IsSchema1() {
			return renderDockerfileSchema1(w, b)
		} else {
			return h.renderDockerfile(w, r, ref, b)
		}
	case "created_by":
		fmt.Fprintf(w, "<pre>")
		if err := renderCreatedBy(w, b); err != nil {
			return err
		}
		fmt.Fprintf(w, "</pre>")
	default:
		return renderJSON(output, b)
	}

	return nil

}

func (h *handler) renderDockerfile(w http.ResponseWriter, r *http.Request, ref name.Reference, b []byte) error {
	manifest := r.URL.Query().Get("manifest")
	if manifest == "" {
		return renderDockerfile(w, b, nil, ref.Context())
	}

	dig, err := name.ParseReference(manifest)
	if err != nil {
		return err
	}
	desc, err := h.fetchManifest(w, r, dig)
	if err != nil {
		return err
	}
	m := v1.Manifest{}
	if err := json.Unmarshal(desc.Manifest, &m); err != nil {
		return err
	}
	return renderDockerfile(w, b, &m, ref.Context())
}

func (h *handler) renderFile(w http.ResponseWriter, r *http.Request, seek io.ReadSeeker) error {
	if mt := r.URL.Query().Get("mt"); mt != "" && !strings.Contains(mt, ".layer.") {
		// Avoid setting this for steve's artifacts stupidity.
		w.Header().Set("Content-Type", mt)
	}

	// Allow this to be cached for an hour.
	w.Header().Set("Cache-Control", "max-age=3600, immutable")

	// TODO: Add render func here?
	httpserve.ServeContent(w, r, "", time.Time{}, seek, nil)

	return nil
}

func (h *handler) renderFS(w http.ResponseWriter, r *http.Request) error {
	dig, ref, err := h.getDigest(w, r)
	if err != nil {
		return fmt.Errorf("getDigest: %w", err)
	}

	index, err := h.getIndex(r.Context(), dig.Identifier())
	if err != nil {
		return fmt.Errorf("indexCache.Index(%q) = %w", dig.Identifier(), err)
	}
	if index != nil {
		return h.renderIndexedFS(w, r, dig, ref, index)
	}

	// Determine if this is actually a filesystem thing.
	blob, ref, err := h.fetchBlob(w, r)
	if err != nil {
		return fmt.Errorf("fetchBlob: %w", err)
	}

	original, unwrapped, err := h.tryNewIndex(w, r, dig, ref, blob)
	if err != nil {
		return fmt.Errorf("failed to index blob %q: %w", dig.String(), err)
	}
	if unwrapped != nil {
		seek := &sizeSeeker{unwrapped, -1, ref, nil, false}
		return h.renderFile(w, r, seek)
	}
	if original != nil {
		seek := &sizeSeeker{original, blob.size, ref, nil, false}
		return h.renderFile(w, r, seek)
	}
	return nil
}

func (h *handler) renderIndexedFS(w http.ResponseWriter, r *http.Request, dig name.Digest, ref string, index soci.Index) error {
	toc := index.TOC()
	if toc == nil {
		return fmt.Errorf("this should not happen")
	}
	mt := r.URL.Query().Get("mt")
	if mt == "" {
		mt = toc.MediaType
	}

	opts := []remote.Option{}
	foreign := strings.HasPrefix(r.URL.Path, "/http/") || strings.HasPrefix(r.URL.Path, "/https/")
	if !foreign {
		// Skip the ping for foreign layers.
		opts = h.remoteOptions(w, r, dig.Context().Name())
	}

	opts = append(opts, remote.WithSize(toc.Csize))

	cachedUrl := ""
	cookie, err := r.Cookie("redirect")
	if err == nil {
		b, err := base64.URLEncoding.DecodeString(cookie.Value)
		if err != nil {
			return err
		}
		var v RedirectCookie
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		if v.Digest == dig.Identifier() {
			cachedUrl = v.Url
		} else {
			cookie = nil
		}
	}

	// For foreign layers, we aren't hitting the registry. We want
	// to reuse some code from remote.BlobSeeker but without the
	// ping/token stuff, so we transport.Wrap a plain transport.
	if foreign {
		p := r.URL.Path
		scheme := "https://"
		if strings.HasPrefix(r.URL.Path, "/http/") {
			p = strings.TrimPrefix(p, "/http/")
			scheme = "http://"
		} else {
			p = strings.TrimPrefix(p, "/https/")
		}
		if before, _, ok := strings.Cut(p, "@"); ok {
			u, err := url.PathUnescape(before)
			if err != nil {
				return err
			}
			u = scheme + u
			cachedUrl = u

			t := remote.DefaultTransport
			t = transport.NewRetry(t)
			t = transport.NewUserAgent(t, ua)
			if r.URL.Query().Get("trace") != "" {
				t = transport.NewTracer(t)
			}
			t = transport.Wrap(t)
			opts = append(opts, remote.WithTransport(t))
		}
	}

	// We can't set the cookie after calling soci.FS because we will
	// have already sent the body. We use remote.LazyBlob because we
	// don't actually need to send any HTTP requests if they're just
	// browsing directories and not loading file content.
	setCookie := func(blob *remote.BlobSeeker) error {
		if cookie != nil || blob.Url == "" {
			return nil
		}
		v := &RedirectCookie{
			Digest: dig.Identifier(),
			Url:    blob.Url,
		}
		logs.Debug.Printf("setting cookie: %v", v)
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		cv := base64.URLEncoding.EncodeToString(b)
		cookie := &http.Cookie{
			Name:     "redirect",
			Value:    cv,
			Expires:  time.Now().Add(time.Minute * 10),
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(w, cookie)

		return nil
	}

	blob := remote.LazyBlob(dig, cachedUrl, setCookie, opts...)
	prefix := strings.TrimPrefix(ref, "/")
	logs.Debug.Printf("prefix = %s", prefix)
	fs := soci.FS(index, blob, prefix, dig.String(), respTooBig, types.MediaType(mt), renderHeader)
	httpserve.FileServer(httpserve.FS(fs)).ServeHTTP(w, r)

	return nil
}

// Flatten layers of an image and serve as a filesystem.
func (h *handler) renderLayers(w http.ResponseWriter, r *http.Request) error {
	dig, ref, err := h.getDigest(w, r)
	if err != nil {
		return err
	}

	opts := h.remoteOptions(w, r, dig.Context().Name())
	opts = append(opts, remote.WithMaxSize(tooBig))

	desc, err := h.fetchManifest(w, r, dig)
	if err != nil {
		return err
	}

	m, err := v1.ParseManifest(bytes.NewReader(desc.Manifest))
	if err != nil {
		return err
	}

	fss := make([]*soci.SociFS, len(m.Layers))
	var g errgroup.Group
	for i, layer := range m.Layers {
		i := i
		size := layer.Size
		digest := layer.Digest
		urls := layer.URLs
		layerRef := dig.Context().Digest(layer.Digest.String())
		mediaType := layer.MediaType

		if digest.String() == emptyDigest {
			continue
		}

		g.Go(func() error {
			index, err := h.getIndex(r.Context(), digest.String())
			if err != nil {
				return fmt.Errorf("indexCache.Index(%q) = %w", dig.Identifier(), err)
			}
			if index == nil {
				l, err := remote.Layer(layerRef)
				if err != nil {
					return err
				}
				rc, err := l.Compressed()
				if err != nil {
					return err
				}

				index, err = h.createIndex(r.Context(), rc, size, digest.String(), 0, string(mediaType))
				if err != nil {
					return fmt.Errorf("createIndex: %w", err)
				}
				if index == nil {
					// Non-indexable blobs are filtered later>
					return nil
				}
			}

			fs, err := h.createFs(w, r, ref, layerRef, index, size, mediaType, urls, opts)
			if err != nil {
				return err
			}
			// NOTE: reverses order
			fss[(len(m.Layers)-1)-i] = fs
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	prefix := strings.TrimPrefix(ref, "/")
	mfs := soci.NewMultiFS(fss, prefix, dig, desc.Size, desc.MediaType, renderDir)

	// Allow this to be cached for an hour.
	w.Header().Set("Cache-Control", "max-age=3600, immutable")

	httpserve.FileServer(httpserve.FS(mfs)).ServeHTTP(w, r)

	return nil
}

func (h *handler) renderIndex(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	idx := 0
	dig, idxs, err := h.getDigest(w, r)
	if err != nil {
		return fmt.Errorf("getDigest: %w", err)
	}
	prefix := fmt.Sprintf("/cache/%s/%s", idxs, dig.String())
	if parsed, err := strconv.ParseInt(idxs, 10, 64); err != nil {
		logs.Debug.Printf("ParseInt(%q)", idxs)
	} else {
		idx = int(parsed)
	}
	key := indexKey(dig.Identifier(), idx)
	size, err := h.indexCache.Size(ctx, key)
	if err != nil {
		return fmt.Errorf("indexCache.Size: %w", err)
	}
	rc, err := h.indexCache.Reader(ctx, key)
	if err != nil {
		return fmt.Errorf("indexCache.Reader: %w", err)
	}
	defer rc.Close()
	zr, err := gzip.NewReader(rc)
	if err != nil {
		return fmt.Errorf("gzip.NewReader: %w", err)
	}
	tr := tar.NewReader(zr)
	fs := h.newLayerFS(tr, size, prefix, dig.String(), "tar+gzip", types.MediaType("application/tar+gzip"))

	// Allow this to be cached for an hour.
	w.Header().Set("Cache-Control", "max-age=3600, immutable")

	httpserve.FileServer(fs).ServeHTTP(w, r)
	return nil
}

func (h *handler) jq(output *jsonOutputter, b []byte, r *http.Request, header *HeaderData) ([]byte, error) {
	jq, ok := r.URL.Query()["jq"]
	if !ok {
		header.JQ += " | jq ."
		return b, nil
	}

	var (
		err error
		exp string
	)

	exps := []string{header.JQ}

	for _, j := range jq {
		if debug {
			log.Printf("j = %s", j)
		}
		b, exp, err = evalBytes(j, b)
		if err != nil {
			return nil, err
		}
		exps = append(exps, exp)
	}

	header.JQ = strings.Join(exps, " | ")
	return b, nil
}

func (h *handler) getTags(repo name.Repository) ([]string, bool) {
	h.Lock()
	tags, ok := h.sawTags[repo.String()]
	h.Unlock()
	return tags, ok
}

func (h *handler) manifestHeader(ref name.Reference, desc v1.Descriptor) *HeaderData {
	header := headerData(ref, desc)
	header.JQ = crane("manifest") + " " + ref.String()

	// Handle clicking repo to list tags and such.
	if strings.Contains(ref.String(), "@") && strings.Index(ref.String(), "@") < strings.Index(ref.String(), ":") {
		chunks := strings.SplitN(ref.String(), "@", 2)
		header.Up = &RepoParent{
			Parent:    ref.Context().String(),
			Child:     chunks[1],
			Separator: "@",
		}
	} else if strings.Contains(ref.String(), ":") {
		chunks := strings.SplitN(ref.String(), ":", 2)
		header.Up = &RepoParent{
			Parent:    ref.Context().String(),
			Child:     chunks[1],
			Separator: ":",
		}
	} else {
		header.Up = &RepoParent{
			Parent: ref.String(),
		}
	}

	// Opportunistically show referrers based on cosign scheme if we
	// have a cached tags list response.
	prefix := strings.Replace(desc.Digest.String(), ":", "-", 1)
	tags, ok := h.getTags(ref.Context())
	if ok {
		for _, tag := range tags {
			if tag == prefix {
				// Referrers tag schema
				header.CosignTags = append(header.CosignTags, CosignTag{
					Tag:   tag,
					Short: "referrers",
				})
			} else if strings.HasPrefix(tag, prefix) {
				// Cosign tag schema
				chunks := strings.SplitN(tag, ".", 2)
				if len(chunks) == 2 && len(chunks[1]) != 0 {
					header.CosignTags = append(header.CosignTags, CosignTag{
						Tag:   tag,
						Short: chunks[1],
					})
				}
			}
		}
	}

	return header
}

func headerData(ref name.Reference, desc v1.Descriptor) *HeaderData {
	return &HeaderData{
		Repo:             ref.Context().String(),
		Reference:        ref.String(),
		CosignTags:       []CosignTag{},
		Descriptor:       &desc,
		Handler:          handlerForMT(string(desc.MediaType)),
		EscapedMediaType: url.QueryEscape(string(desc.MediaType)),
		MediaTypeLink:    getLink(string(desc.MediaType)),
	}
}

func renderHeader(w http.ResponseWriter, fname string, prefix string, ref name.Reference, kind string, mediaType types.MediaType, size int64, f httpserve.File, ctype string) error {
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

	tarh, ok := stat.Sys().(*tar.Header)
	if ok {
		filename = tarh.Name
	} else {
		if !stat.IsDir() {
			logs.Debug.Printf("not a tar header or directory")
		}
	}

	tarflags := "tar -Ox "
	if kind == "tar+gzip" {
		tarflags = "tar -Oxz "
	} else if kind == "tar+zstd" {
		tarflags = "tar --zstd -Ox "
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

	desc := v1.Descriptor{
		Size:      size,
		Digest:    hash,
		MediaType: mediaType,
	}
	header := headerData(ref, desc)
	header.Up = &RepoParent{
		Parent:    ref.Context().String(),
		Separator: "@",
		Child:     ref.Identifier(),
	}
	header.JQ = crane("blob") + " " + ref.String() + " | " + tarflags + " " + filelink

	truncate := int64(1 << 15)
	if stat.Size() > truncate {
		header.JQ = header.JQ + fmt.Sprintf(" | head -c %d", truncate)
		if ctype == "application/octet-stream" {
			header.JQ = header.JQ + " | xxd"
		}
	}

	if stat.IsDir() {
		tarflags = "tar -tv "
		if kind == "tar+gzip" {
			tarflags = "tar -tvz "
		} else if kind == "tar+zstd" {
			tarflags = "tar --zstd -tv "
		}

		header.JQ = crane("blob") + " " + ref.String() + " | " + tarflags + " " + filelink
	}

	return bodyTmpl.Execute(w, header)
}

func renderDir(w http.ResponseWriter, fname string, prefix string, mediaType types.MediaType, size int64, ref name.Reference, f httpserve.File, ctype string) error {
	// This must be a directory because it wasn't part of a filesystem
	stat, err := f.Stat()
	if err != nil {
		return err
	}
	if !stat.IsDir() {
		return fmt.Errorf("file was not a directory")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := headerTmpl.Execute(w, TitleData{ref.String()}); err != nil {
		return err
	}

	filename := strings.TrimPrefix(fname, "/"+prefix)
	filename = strings.TrimPrefix(filename, "/")

	sys := stat.Sys()
	tarh, ok := sys.(*tar.Header)
	if ok {
		filename = tarh.Name
	} else {
		logs.Debug.Printf("sys: %T", sys)
	}

	tarflags := "tar -tv "

	hash, err := v1.NewHash(ref.Identifier())
	if err != nil {
		return err
	}

	desc := v1.Descriptor{
		Size:      size,
		Digest:    hash,
		MediaType: mediaType,
	}
	header := headerData(ref, desc)

	header.Up = &RepoParent{
		Parent:    ref.Context().String(),
		Separator: "@",
		Child:     ref.Identifier(),
	}

	// TODO: Make filename clickable to go up a directory.
	header.JQ = crane("export") + " " + ref.String() + " | " + tarflags + " " + filename

	return bodyTmpl.Execute(w, header)
}
