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
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"compress/gzip"
	ogzip "compress/gzip"

	"github.com/google/go-containerregistry/internal/and"
	"github.com/google/go-containerregistry/internal/httpserve"
	"github.com/google/go-containerregistry/internal/soci"
	"github.com/google/go-containerregistry/internal/verify"
	"github.com/google/go-containerregistry/pkg/authn"
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
const spanSize = 1 << 22

var whitespaceRegex = regexp.MustCompile(`( )(?:    )+`)

func whitespaceRepl(in []byte) []byte {
	return bytes.Replace(in, []byte(" "), []byte(" \\\n"), 1)
}

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

	h.mux.HandleFunc("/", h.root)
	h.mux.HandleFunc("/fs/", h.fsHandler)
	h.mux.HandleFunc("/layers/", h.layersHandler)

	// Janky workaround for downloading via the "urls" field.
	h.mux.HandleFunc("/http/", h.fsHandler)
	h.mux.HandleFunc("/https/", h.fsHandler)

	// Try to detect mediaType.
	h.mux.HandleFunc("/blob/", h.fsHandler)
	h.mux.HandleFunc("/cache/", h.indexHandler)

	// We know it's JSON.
	h.mux.HandleFunc("/json/", h.fsHandler)

	h.mux.HandleFunc("/oauth", h.oauthHandler)

	//TODO: APK?
	// curl https://packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz | tar -tvzf -
	// curl https://packages.wolfi.dev/os/x86_64/giflib-doc-5.2.1-r0.apk | tar -tzvf -

	return &h
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

// Like http.Handler, but with error handling.
func (h *handler) root(w http.ResponseWriter, r *http.Request) {
	if err := h.renderResponse(w, r); err != nil {
		if err := h.maybeOauthErr(w, r, err); err != nil {
			log.Printf("renderResponse: %v", err)
			fmt.Fprintf(w, "failed: %s", html.EscapeString(err.Error()))
		}
	}
}

// Like http.Handler, but with error handling.
func (h *handler) fsHandler(w http.ResponseWriter, r *http.Request) {
	if err := h.renderBlob(w, r); err != nil {
		if err := h.maybeOauthErr(w, r, err); err != nil {
			log.Printf("renderBlob: %v", err)
			fmt.Fprintf(w, "failed: %s", html.EscapeString(err.Error()))
		}
	}
}

func (h *handler) remoteOptions(w http.ResponseWriter, r *http.Request, repo string) []remote.Option {
	ctx := r.Context()

	// TODO: Set timeout.
	opts := []remote.Option{}
	opts = append(opts, h.remote...)
	opts = append(opts, remote.WithContext(ctx))

	auth := authn.Anonymous

	parsed, err := name.NewRepository(repo)
	if err == nil && isGoogle(parsed.Registry.String()) {
		if at, err := r.Cookie("access_token"); err == nil {
			tok := &oauth2.Token{
				AccessToken: at.Value,
				Expiry:      at.Expires,
			}
			if rt, err := r.Cookie("refresh_token"); err == nil {
				tok.RefreshToken = rt.Value
			}
			if h.oauth != nil {
				ts := h.oauth.TokenSource(r.Context(), tok)
				auth = google.NewTokenSourceAuthenticator(ts)
			}

		}
	}

	opts = append(opts, remote.WithAuth(auth))

	if t, err := h.transportFromCookie(w, r, repo, auth); err != nil {
		log.Printf("failed to get transport from cookie: %v", err)
	} else {
		opts = append(opts, remote.WithTransport(t))
	}

	if n := r.URL.Query().Get("n"); n != "" {
		size, err := strconv.ParseInt(n, 10, 64)
		if err != nil {
			log.Printf("n = %s, err: %v", n, err)
		} else {
			opts = append(opts, remote.WithPageSize(int(size)))
		}
	}
	if next := r.URL.Query().Get("next"); next != "" {
		opts = append(opts, remote.WithNext(next))
	}

	return opts
}

func (h *handler) renderResponse(w http.ResponseWriter, r *http.Request) error {
	qs := r.URL.Query()

	if images, ok := qs["image"]; ok {
		return h.renderManifest(w, r, images[0])
	}
	if blobs, ok := qs["blob"]; ok {
		return h.renderBlobJSON(w, r, blobs[0])
	}
	// We shouldn't hit this anymore, but keep these around for backward compat.
	if blob, ok := getBlobQuery(r); ok {
		return h.renderBlobJSON(w, r, blob)
	}
	if repos, ok := qs["repo"]; ok {
		return h.renderRepo(w, r, repos[0])
	}

	// Fall back to a helpful landing page.
	return renderLanding(w)
}

func renderLanding(w http.ResponseWriter) error {
	w.Header().Set("Cache-Control", "max-age=60")
	_, err := io.Copy(w, strings.NewReader(landingPage))
	return err
}

func (h *handler) getTags(repo name.Repository) ([]string, bool) {
	h.Lock()
	tags, ok := h.sawTags[repo.String()]
	h.Unlock()
	return tags, ok
}

// Render repo with tags linking to images.
func (h *handler) renderRepo(w http.ResponseWriter, r *http.Request, repo string) error {
	qs := r.URL.Query()
	ref, err := name.NewRepository(repo)
	if err != nil {
		return err
	}

	if ref.RegistryStr() == "registry.k8s.io" || ref.RegistryStr() == "mirror.gcr.io" || (isGoogle(ref.RegistryStr()) && ref.RepositoryStr() != "") {
		return h.renderGoogleRepo(w, r, repo)
	} else if ref.RepositoryStr() == "" {
		return h.renderCatalog(w, r, repo)
	}
	if (strings.HasPrefix(repo, "docker.io") || strings.HasPrefix(repo, name.DefaultRegistry)) && strings.Count(repo, "/") == 1 {
		return h.renderDockerHub(w, r, repo)
	}

	if err := headerTmpl.Execute(w, TitleData{repo}); err != nil {
		return err
	}
	data := HeaderData{
		Repo:      repo,
		Reference: repo,
		JQ:        crane + " ls " + repo,
	}
	if strings.Contains(repo, "/") || (ref.RegistryStr() == name.DefaultRegistry || ref.RegistryStr() == "docker.io") {
		fullRepo := path.Join(ref.RegistryStr(), ref.RepositoryStr())
		base := path.Base(fullRepo)
		dir := path.Dir(strings.TrimRight(fullRepo, "/"))
		if base != "." && dir != "." {
			data.Up = &RepoParent{
				Parent:    dir,
				Child:     base,
				Separator: "/",
			}
		}
	}
	if err := bodyTmpl.Execute(w, data); err != nil {
		return err
	}

	output := &jsonOutputter{
		w:     w,
		u:     r.URL,
		fresh: []bool{},
		repo:  repo,
	}

	var v *remote.Tags
	if qs.Get("n") != "" {
		v, err = remote.ListPage(ref, qs.Get("next"), h.remoteOptions(w, r, repo)...)
		if err != nil {
			return err
		}
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		opts := h.remoteOptions(w, r, repo)
		opts = append(opts, remote.WithContext(ctx))

		v, err = remote.List(ref, opts...)
		if err != nil {
			if v != nil && errors.Is(err, context.DeadlineExceeded) {
				fmt.Fprintf(w, "<p>deadline exceeded, returning partial response</p>\n<hr>\n")
			} else {
				return err
			}
		}
		h.Lock()
		h.sawTags[ref.String()] = v.Tags
		h.Unlock()
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
	data := HeaderData{
		Repo:      repo,
		Reference: repo,
	}
	if ref.RepositoryStr() == "" {
		uri := &url.URL{
			Scheme: ref.Registry.Scheme(),
			Host:   ref.Registry.RegistryStr(),
			Path:   "/v2/tags/list",
		}
		data.JQ = fmt.Sprintf("curl -sL %q | jq .", uri.String())
	} else {
		data.JQ = gcrane + " ls --json " + repo + " | jq ."
	}
	if strings.Contains(repo, "/") {
		base := path.Base(repo)
		dir := path.Dir(strings.TrimRight(repo, "/"))
		if base != "." && dir != "." {
			data.Up = &RepoParent{
				Parent:    dir,
				Child:     base,
				Separator: "/",
			}
		}
	}
	if err := bodyTmpl.Execute(w, data); err != nil {
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
	data := HeaderData{
		Repo:      repo,
		Reference: repo,
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
	data.JQ = fmt.Sprintf("curl -sL %q | jq .", nextUri)

	if strings.Contains(repo, "/") {
		base := path.Base(repo)
		dir := path.Dir(strings.TrimRight(repo, "/"))
		if base != "." && dir != "." {
			data.Up = &RepoParent{
				Parent:    dir,
				Child:     base,
				Separator: "/",
			}
		}
	}
	if err := bodyTmpl.Execute(w, data); err != nil {
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
	qs := r.URL.Query()
	ref, err := name.NewRepository(repo)
	if err != nil {
		return err
	}
	if err := headerTmpl.Execute(w, TitleData{repo}); err != nil {
		return err
	}
	data := HeaderData{
		Repo:      repo,
		Reference: repo,
		JQ:        crane + " catalog " + repo,
	}
	if err := bodyTmpl.Execute(w, data); err != nil {
		return err
	}

	output := &jsonOutputter{
		w:     w,
		u:     r.URL,
		fresh: []bool{},
		repo:  repo,
	}
	var v *remote.Catalogs
	if qs.Get("n") != "" {
		v, err = remote.CatalogPage(ref.Registry, qs.Get("next"), h.remoteOptions(w, r, repo)...)
		if err != nil {
			return err
		}
	} else {
		repos, err := remote.Catalog(r.Context(), ref.Registry, h.remoteOptions(w, r, repo)...)
		if err != nil {
			return err
		}

		v = &remote.Catalogs{
			Repos: repos,
		}
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
	var (
		desc *remote.Descriptor
		opts []remote.Option
	)
	allowCache := true
	if isGoogle(ref.Context().Registry.String()) {
		if _, err := r.Cookie("access_token"); err == nil {
			allowCache = false
		}
	}
	if allowCache {
		if _, ok := ref.(name.Digest); ok {
			desc, ok = h.manifests[ref.Identifier()]
		} else {
			if ref.Context().Registry.String() == name.DefaultRegistry {
				// For dockerhub, HEAD tags to avoid rate limiting
				// since we might have things cached...
				opts = h.remoteOptions(w, r, ref.Context().Name())
				opts = append(opts, remote.WithMaxSize(tooBig))
				d, err := remote.Head(ref, opts...)
				if err == nil {
					desc, ok = h.manifests[d.Digest.String()]
				}
			}
		}
	}
	if desc == nil {
		if opts == nil {
			opts = h.remoteOptions(w, r, ref.Context().Name())
			opts = append(opts, remote.WithMaxSize(tooBig))
		}

		var g errgroup.Group
		g.Go(func() error {
			desc, err = remote.Get(ref, opts...)
			if err != nil {
				return err
			}
			h.manifests[desc.Digest.String()] = desc
			return nil
		})
		if dig, ok := ref.(name.Digest); ok {
			g.Go(func() error {
				if _, ok := h.getTags(ref.Context()); ok {
					return nil
				}
				fallback := strings.ReplaceAll(dig.Identifier(), ":", "-")
				ref := ref.Context().Tag(fallback)
				if _, err := remote.Head(ref, opts...); err != nil {
					log.Printf("fallback check: %v", err)
					return nil
				}

				h.Lock()
				defer h.Unlock()
				if _, ok := h.sawTags[ref.Context().String()]; ok {
					return nil
				}
				h.sawTags[ref.Context().String()] = []string{fallback}

				return nil
			})
		}
		if err := g.Wait(); err != nil {
			return err
		}
	}

	jqref, err := url.PathUnescape(ref.String())
	if err != nil {
		return err
	}

	data := HeaderData{
		Repo: ref.Context().String(),
		//Reference:  url.QueryEscape(ref.String()),
		Reference:  ref.String(),
		CosignTags: []CosignTag{},
		Descriptor: &v1.Descriptor{
			Digest:    desc.Digest,
			MediaType: desc.MediaType,
			Size:      desc.Size,
		},
		Handler:          handlerForMT(string(desc.MediaType)),
		EscapedMediaType: url.QueryEscape(string(desc.MediaType)),
		MediaTypeLink:    getLink(string(desc.MediaType)),
		JQ:               crane + " manifest " + jqref,
	}

	if strings.Contains(ref.String(), "@") && strings.Index(ref.String(), "@") < strings.Index(ref.String(), ":") {
		chunks := strings.SplitN(ref.String(), "@", 2)
		data.Up = &RepoParent{
			Parent:    ref.Context().String(),
			Child:     chunks[1],
			Separator: "@",
		}
	} else if strings.Contains(ref.String(), ":") {
		chunks := strings.SplitN(ref.String(), ":", 2)
		data.Up = &RepoParent{
			Parent:    ref.Context().String(),
			Child:     chunks[1],
			Separator: ":",
		}
	} else {
		data.Up = &RepoParent{
			Parent: ref.String(),
		}
	}
	prefix := strings.Replace(desc.Digest.String(), ":", "-", 1)
	tags, ok := h.getTags(ref.Context())
	if ok {
		for _, tag := range tags {
			if tag == prefix {
				// Referrers tag schema
				data.CosignTags = append(data.CosignTags, CosignTag{
					Tag:   tag,
					Short: "referrers",
				})
			} else if strings.HasPrefix(tag, prefix) {
				// Cosign tag schema
				chunks := strings.SplitN(tag, ".", 2)
				if len(chunks) == 2 && len(chunks[1]) != 0 {
					data.CosignTags = append(data.CosignTags, CosignTag{
						Tag:   tag,
						Short: chunks[1],
					})
				}
			}
		}
	}

	u := *r.URL
	if _, ok := ref.(name.Digest); ok {
		// Allow this to be cached for an hour.
		w.Header().Set("Cache-Control", "max-age=3600, immutable")
	} else {
		newImage := image + "@" + desc.Digest.String()
		qs := u.Query()
		qs.Set("image", newImage)
		u.RawQuery = qs.Encode()
	}

	if err := headerTmpl.Execute(w, TitleData{image}); err != nil {
		return err
	}

	output := &jsonOutputter{
		w:     w,
		u:     &u,
		fresh: []bool{},
		repo:  ref.Context().String(),
		mt:    string(desc.MediaType),
		pt:    r.URL.Query().Get("payloadType"),
	}

	// Mutates data for bodyTmpl.
	b, err := h.jq(output, desc.Manifest, r, &data)
	if err != nil {
		return err
	}

	if r.URL.Query().Get("render") == "x509" {
		if bytes.Count(b, []byte("-----BEGIN CERTIFICATE-----")) > 1 {
			data.JQ += " | while openssl x509 -text -noout 2>/dev/null; do :; done"
		} else {
			data.JQ += " | openssl x509 -text -noout"
		}
	} else if r.URL.Query().Get("render") == "history" {
		data.JQ = strings.TrimSuffix(data.JQ, " | jq .")
		data.JQ += ` | jq '.history[] | .v1Compatibility' -r | jq '.container_config.Cmd | join(" ")' -r | tac`
	}

	if err := bodyTmpl.Execute(w, data); err != nil {
		return err
	}

	if r.URL.Query().Get("render") == "cert" {
		u := *r.URL
		qs := u.Query()
		qs.Set("render", "x509")
		u.RawQuery = qs.Encode()

		fmt.Fprintf(w, `<div><a href="%s">`, u.String())

		for _, line := range bytes.Split(b, []byte("\n")) {
			if _, err := w.Write(line); err != nil {
				return err
			}
			fmt.Fprintf(w, "<br>")
		}
		fmt.Fprintf(w, "</a></div>")
	} else if r.URL.Query().Get("render") == "x509" {
		fmt.Fprintf(w, "<pre>")
		if err := renderCert(w, b); err != nil {
			return err
		}
		fmt.Fprintf(w, "</pre>")
	} else if r.URL.Query().Get("render") == "raw" {
		fmt.Fprintf(w, "<pre>")
		if _, err := w.Write(b); err != nil {
			return err
		}
		fmt.Fprintf(w, "</pre>")
	} else if r.URL.Query().Get("render") == "history" {
		fmt.Fprintf(w, "<pre>")
		if err := renderDockerfileSchema1(w, b); err != nil {
			return nil
		}
		fmt.Fprintf(w, "</pre>")
	} else {
		if err := renderJSON(output, b); err != nil {
			return err
		}
	}

	fmt.Fprintf(w, footer)

	return nil
}

// Render blob as JSON, possibly containing refs to images.
func (h *handler) renderBlobJSON(w http.ResponseWriter, r *http.Request, blobRef string) error {
	var (
		size int64
		blob io.ReadCloser
		err  error
		ref  name.Reference
	)
	if blobRef != "" {
		dig, err := name.NewDigest(blobRef)
		if err != nil {
			return err
		}
		ref = dig

		opts := h.remoteOptions(w, r, dig.Context().Name())
		opts = append(opts, remote.WithMaxSize(tooBig))
		l, err := remote.Layer(dig, opts...)
		if err != nil {
			return err
		}
		blob, err = l.Compressed()
		if err != nil {
			return err
		}
		defer blob.Close()
		size, err = l.Size()
		if err != nil {
			log.Printf("layer %s Size(): %v", ref, err)
			return fmt.Errorf("cannot check blob size: %v", err)
		} else if size > tooBig {
			return fmt.Errorf("layer %s too big: %d", ref, size)
		}
	} else {
		fetched, prefix, err := h.fetchBlob(w, r)
		if err != nil {
			return err
		}
		defer fetched.Close()
		_, root, err := splitFsURL(r.URL.Path)
		if err != nil {
			return err
		}
		trimmed := strings.TrimPrefix(prefix, root)
		ref, err = name.NewDigest(trimmed)
		if err != nil {
			return err
		}

		blob = fetched
		size = fetched.size
	}

	// Allow this to be cached for an hour.
	w.Header().Set("Cache-Control", "max-age=3600, immutable")

	if err := headerTmpl.Execute(w, TitleData{blobRef}); err != nil {
		return err
	}

	digest := ref.Identifier()
	hash, err := v1.NewHash(digest)
	if err != nil {
		return err
	}

	output := &jsonOutputter{
		w:     w,
		u:     r.URL,
		fresh: []bool{},
		repo:  ref.Context().String(),
		pt:    r.URL.Query().Get("payloadType"),
		mt:    r.URL.Query().Get("mt"),
	}

	mediaType := types.MediaType("application/octet-stream")
	if output.mt != "" {
		mediaType = types.MediaType(output.mt)
	}

	data := HeaderData{
		Repo:      ref.Context().String(),
		Reference: url.QueryEscape(ref.String()),
		Descriptor: &v1.Descriptor{
			Size:      size,
			Digest:    hash,
			MediaType: mediaType,
		},
		Handler:          handlerForMT(string(mediaType)),
		EscapedMediaType: url.QueryEscape(string(mediaType)),
		MediaTypeLink:    getLink(string(mediaType)),
		Up: &RepoParent{
			Parent:    ref.Context().String(),
			Separator: "@",
			Child:     ref.Identifier(),
		},
		JQ: crane + " blob " + ref.String(),
	}

	// TODO: Can we do this in a streaming way?
	input, err := ioutil.ReadAll(io.LimitReader(blob, tooBig))
	if err != nil {
		return err
	}

	// Mutates data for bodyTmpl.
	b, err := h.jq(output, input, r, &data)
	if err != nil {
		return err
	}

	if r.URL.Query().Get("render") == "history" {
		data.JQ = strings.TrimSuffix(data.JQ, " | jq .")
		data.JQ += " | jq '.history[] | .created_by' -r"

	} else if r.URL.Query().Get("render") == "der" {
		data.JQ += " | openssl x509 -inform der -text -noout"
	}

	if err := bodyTmpl.Execute(w, data); err != nil {
		return err
	}

	if r.URL.Query().Get("render") == "raw" {
		fmt.Fprintf(w, "<pre>")
		if _, err := w.Write(b); err != nil {
			return err
		}
		fmt.Fprintf(w, "</pre>")
	} else if r.URL.Query().Get("render") == "der" {
		fmt.Fprintf(w, "<pre>")
		if err := renderDer(w, b); err != nil {
			return err
		}
		fmt.Fprintf(w, "</pre>")

	} else if r.URL.Query().Get("render") == "history" {
		fmt.Fprintf(w, "<pre>")
		if err := renderDockerfile(w, b); err != nil {
			return nil
		}
		fmt.Fprintf(w, "</pre>")
	} else if r.URL.Query().Get("render") == "created_by" {
		fmt.Fprintf(w, "<pre>")
		if err := renderCreatedBy(w, b); err != nil {
			return nil
		}
		fmt.Fprintf(w, "</pre>")
	} else {
		if err := renderJSON(output, b); err != nil {
			return err
		}
	}

	fmt.Fprintf(w, footer)

	return nil
}

func (h *handler) indexHandler(w http.ResponseWriter, r *http.Request) {
	if err := h.renderIndex(w, r); err != nil {
		log.Printf("renderIndex: %v", err)
		fmt.Fprintf(w, "failed: %s", html.EscapeString(err.Error()))
	}
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

// Render blob, either as just ungzipped bytes, or via http.FileServer.
func (h *handler) renderBlob(w http.ResponseWriter, r *http.Request) error {
	if strings.HasPrefix(r.URL.Path, "/json/") {
		return h.renderBlobJSON(w, r, "")
	}

	qs := r.URL.Query()
	mt := qs.Get("mt")

	dig, ref, err := h.getDigest(w, r)
	if err != nil {
		return fmt.Errorf("getDigest: %w", err)
	}

	var (
		index soci.Index
	)
	if h.indexCache != nil {
		index, err = h.getIndex(r.Context(), dig.Identifier())
		if err != nil {
			logs.Debug.Printf("indexCache.Index(%q) = %v", dig.Identifier(), err)
		} else {
			logs.Debug.Printf("indexCache hit: %s", dig.Identifier())
			if mt == "" {
				toc := index.TOC()
				if toc != nil {
					mt = toc.MediaType
				}
			}
		}
	}

	foreign := strings.HasPrefix(ref, "/http/") || strings.HasPrefix(ref, "/https/")
	shouldIndex := index == nil
	if index != nil && index.TOC() != nil {
		opts := []remote.Option{}
		if !foreign {
			// Skip the ping for foreign layers.
			opts = h.remoteOptions(w, r, dig.Context().Name())
		}

		opts = append(opts, remote.WithSize(index.TOC().Csize))

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
				logs.Debug.Printf("%q vs %q", v.Digest, dig.Identifier())
				// Clear so we reset it.
				cookie = nil
			}
		} else {
			logs.Debug.Printf("redirect cookie err: %v", err)
		}

		if h, s := strings.HasPrefix(ref, "/http/"), strings.HasPrefix(ref, "/https/"); h || s {
			p := ref
			if h {
				p = strings.TrimPrefix(p, "/http/")
			} else {
				p = strings.TrimPrefix(ref, "/https/")
			}
			chunks := strings.SplitN(p, "@", 2)
			if len(chunks) == 2 {
				u, err := url.PathUnescape(chunks[0])
				if err != nil {
					return err
				}
				scheme := "https://"
				if h {
					scheme = "http://"
				}
				u = scheme + u
				logs.Debug.Printf("u = %q", u)
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
		logs.Debug.Printf("soci serve")
		// We never saw a non-nil Body, we can do the range.
		prefix := strings.TrimPrefix(ref, "/")
		logs.Debug.Printf("prefix = %s", prefix)
		fs := soci.FS(index, blob, prefix, dig.String(), respTooBig, types.MediaType(mt))
		fs.Render = renderHeader
		httpserve.FileServer(httpserve.FS(fs)).ServeHTTP(w, r)

		return nil
	}

	// Determine if this is actually a filesystem thing.
	blob, ref, err := h.fetchBlob(w, r)
	if err != nil {
		return err
	}
	size := blob.size
	var rc io.ReadCloser = blob

	logs.Debug.Printf("shouldIndex: %t", shouldIndex)
	if shouldIndex {
		ocw, err := h.indexCache.Writer(r.Context(), indexKey(dig.Identifier(), 0))
		if err != nil {
			return fmt.Errorf("indexCache.Writer: %w", err)
		}
		defer ocw.Close()
		zw, err := ogzip.NewWriterLevel(ocw, ogzip.BestSpeed)
		if err != nil {
			return err
		}
		bw := bufio.NewWriterSize(zw, 1<<16)
		flushClose := func() error {
			if err := bw.Flush(); err != nil {
				return err
			}
			return zw.Close()
		}
		cw := &and.WriteCloser{bw, flushClose}

		indexer, _, err := soci.NewIndexer(blob, cw, spanSize, mt)
		if err != nil {
			return fmt.Errorf("TODO: don't return this error: %w", err)
		}
		fs := h.newLayerFS(indexer, size, ref, dig.String(), indexer.Type(), types.MediaType(mt))
		httpserve.FileServer(fs).ServeHTTP(w, r)

		for {
			// Make sure we hit the end.
			_, err := indexer.Next()
			if errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				return fmt.Errorf("indexer.Next: %w", err)
			}
		}

		toc, err := indexer.TOC()
		if err != nil {
			return err
		}
		if h.tocCache != nil {
			key := indexKey(dig.Identifier(), 0)
			if err := h.tocCache.Put(r.Context(), key, toc); err != nil {
				logs.Debug.Printf("cache.Put(%q) = %v", key, err)
			}
		}

		logs.Debug.Printf("index size: %d", indexer.Size())

		return nil
	}

	kind, pr, _, err := soci.Peek(rc)
	if err != nil {
		return fmt.Errorf("TODO: don't return this error: %w", err)
	}
	if kind == "tar" {
		// TODO: Remove newLayerFS entirely?
		fs := h.newLayerFS(tar.NewReader(pr), size, ref, dig.String(), kind, types.MediaType(mt))

		// Allow this to be cached for an hour.
		w.Header().Set("Cache-Control", "max-age=3600, immutable")

		httpserve.FileServer(fs).ServeHTTP(w, r)

		return nil
	}

	if mt != "" && !strings.Contains(mt, ".layer.") {
		// Avoid setting this for steve's artifacts stupidity.
		w.Header().Set("Content-Type", mt)
	}
	qsize := qs.Get("size")
	if qsize != "" {
		if sz, err := strconv.ParseInt(qsize, 10, 64); err != nil {
			log.Printf("wtf? %q size=%q", ref, qsize)
		} else {
			size = sz
		}
	}

	if debug {
		log.Printf("size=%d", size)
	}

	// Allow this to be cached for an hour.
	w.Header().Set("Cache-Control", "max-age=3600, immutable")

	seek := &sizeSeeker{rc, size, ref, nil, false}
	httpserve.ServeContent(w, r, "", time.Time{}, seek, nil)

	return nil
}
func (h *handler) layersHandler(w http.ResponseWriter, r *http.Request) {
	if err := h.renderLayers(w, r); err != nil {
		if err := h.maybeOauthErr(w, r, err); err != nil {
			log.Printf("renderLayers: %v", err)
			fmt.Fprintf(w, "failed: %s", html.EscapeString(err.Error()))
		}
	}
}

// Flatten layers of an image and serve as a filesystem.
func (h *handler) renderLayers(w http.ResponseWriter, r *http.Request) error {
	logs.Debug.Printf("renderLayers")
	dig, ref, err := h.getDigest(w, r)
	if err != nil {
		return err
	}

	var (
		desc *remote.Descriptor
		opts []remote.Option
	)
	allowCache := true
	if isGoogle(dig.Context().Registry.String()) {
		if _, err := r.Cookie("access_token"); err == nil {
			allowCache = false
		}
	}
	if allowCache {
		desc, _ = h.manifests[dig.Identifier()]
	}

	if opts == nil {
		opts = h.remoteOptions(w, r, dig.Context().Name())
		opts = append(opts, remote.WithMaxSize(tooBig))
	}

	if desc == nil {
		desc, err = remote.Get(dig, opts...)
		if err != nil {
			return err
		}
		h.manifests[desc.Digest.String()] = desc
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
			// TODO: Non-targz should fail gracefully.
			continue
		}

		g.Go(func() error {
			var (
				index soci.Index
				err   error
			)
			if h.indexCache != nil {
				index, err = h.getIndex(r.Context(), digest.String())
				if err != nil {
					logs.Debug.Printf("indexCache.Index(%q) = %v", digest.String(), err)
				} else {
					logs.Debug.Printf("indexCache hit: %s", digest.String())
				}
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
	mfs := soci.NewMultiFS(fss, prefix, dig, renderDir, desc.Size, desc.MediaType)

	// Allow this to be cached for an hour.
	w.Header().Set("Cache-Control", "max-age=3600, immutable")

	httpserve.FileServer(httpserve.FS(mfs)).ServeHTTP(w, r)

	return nil
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

	header, ok := stat.Sys().(*tar.Header)
	if ok {
		filename = header.Name
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

	data := HeaderData{
		Repo:      ref.Context().String(),
		Reference: ref.String(),
		Descriptor: &v1.Descriptor{
			Size:      size,
			Digest:    hash,
			MediaType: mediaType,
		},
		Handler:       handlerForMT(string(mediaType)),
		MediaTypeLink: getLink(string(mediaType)),
		Up: &RepoParent{
			Parent:    ref.Context().String(),
			Separator: "@",
			Child:     ref.Identifier(),
		},
		JQ: crane + " blob " + ref.String() + " | " + tarflags + " " + filelink,
	}
	truncate := int64(1 << 15)
	if stat.Size() > truncate {
		data.JQ = data.JQ + fmt.Sprintf(" | head -c %d", truncate)
		if ctype == "application/octet-stream" {
			data.JQ = data.JQ + " | xxd"
		}
	}

	if stat.IsDir() {
		tarflags = "tar -tv "
		if kind == "tar+gzip" {
			tarflags = "tar -tvz "
		} else if kind == "tar+zstd" {
			tarflags = "tar --zstd -tv "
		}

		data.JQ = crane + " blob " + ref.String() + " | " + tarflags + " " + filelink
	}

	if err := bodyTmpl.Execute(w, data); err != nil {
		return err
	}
	return nil
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

	// TODO: Make filename clickable to go up a directory.
	filename := strings.TrimPrefix(fname, "/"+prefix)
	filename = strings.TrimPrefix(filename, "/")

	sys := stat.Sys()
	header, ok := sys.(*tar.Header)
	if ok {
		filename = header.Name
	} else {
		logs.Debug.Printf("sys: %T", sys)
	}

	tarflags := "tar -tv "

	hash, err := v1.NewHash(ref.Identifier())
	if err != nil {
		return err
	}

	data := HeaderData{
		Repo:      ref.Context().String(),
		Reference: ref.String(),
		Descriptor: &v1.Descriptor{
			Size:      size,
			Digest:    hash,
			MediaType: mediaType,
		},
		Handler: handlerForMT(string(mediaType)),
		//EscapedMediaType: url.QueryEscape(string(mediaType)),
		MediaTypeLink: getLink(string(mediaType)),
		Up: &RepoParent{
			Parent:    ref.Context().String(),
			Separator: "@",
			Child:     ref.Identifier(),
		},
		JQ: crane + " export " + ref.String() + " | " + tarflags + " " + filename,
	}

	if err := bodyTmpl.Execute(w, data); err != nil {
		return err
	}
	return nil
}

func (h *handler) createIndex(ctx context.Context, rc io.ReadCloser, size int64, prefix string, idx int, mediaType string) (soci.Index, error) {
	key := indexKey(prefix, idx)
	if debug {
		logs.Debug.Printf("createIndex(%q)", key)
		start := time.Now()
		defer func() {
			log.Printf("createIndex(%q) (%s)", key, time.Since(start))
		}()
	}

	ocw, err := h.indexCache.Writer(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("indexCache.Writer: %w", err)
	}
	defer ocw.Close()

	zw, err := ogzip.NewWriterLevel(ocw, ogzip.BestSpeed)
	if err != nil {
		return nil, fmt.Errorf("ogzip.NewWriterLevel: %w", err)
	}

	bw := bufio.NewWriterSize(zw, 1<<16)
	flushClose := func() error {
		if err := bw.Flush(); err != nil {
			logs.Debug.Printf("Flush: %v", err)
			return err
		}
		return zw.Close()
	}
	cw := &and.WriteCloser{bw, flushClose}

	indexer, _, err := soci.NewIndexer(rc, cw, spanSize, mediaType)
	if err != nil {
		return nil, fmt.Errorf("TODO: don't return this error: %w", err)
	}
	for {
		// Make sure we hit the end.
		_, err := indexer.Next()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("indexer.Next: %w", err)
		}
	}

	toc, err := indexer.TOC()
	if err != nil {
		return nil, fmt.Errorf("TOC: %w", err)
	}
	if h.tocCache != nil {
		if err := h.tocCache.Put(ctx, key, toc); err != nil {
			logs.Debug.Printf("cache.Put(%q) = %v", key, err)
		}
	}
	logs.Debug.Printf("index size: %d", indexer.Size())

	if err := ocw.Close(); err != nil {
		return nil, fmt.Errorf("ocw.Close: %w", err)
	}

	return h.getIndexN(ctx, prefix, idx)
}

func (h *handler) createFs(w http.ResponseWriter, r *http.Request, ref string, dig name.Digest, index soci.Index, size int64, mt types.MediaType, urls []string, opts []remote.Option) (*soci.SociFS, error) {
	if opts == nil {
		opts = h.remoteOptions(w, r, dig.Context().Name())
	}
	opts = append(opts, remote.WithSize(size))

	cachedStr := ""
	if len(urls) > 0 {
		cachedStr = urls[0]
	}
	blob := remote.LazyBlob(dig, cachedStr, nil, opts...)

	// We never saw a non-nil Body, we can do the range.
	prefix := strings.TrimPrefix(ref, "/")
	fs := soci.FS(index, blob, prefix, dig.String(), respTooBig, mt)
	fs.Render = renderHeader
	return fs, nil
}

// parse ref out of r
// this is duplicated and desperately needs refactoring
func (h *handler) getDigest(w http.ResponseWriter, r *http.Request) (name.Digest, string, error) {
	path, root, err := splitFsURL(r.URL.Path)
	if err != nil {
		return name.Digest{}, "", err
	}

	chunks := strings.SplitN(path, "@", 2)
	if len(chunks) != 2 {
		return name.Digest{}, "", fmt.Errorf("not enough chunks: %s", path)
	}
	// 71 = len("sha256:") + 64
	if len(chunks[1]) < 71 {
		return name.Digest{}, "", fmt.Errorf("second chunk too short: %s", chunks[1])
	}

	digest := chunks[1][:71]

	ref := strings.Join([]string{chunks[0], digest}, "@")
	if ref == "" {
		return name.Digest{}, "", fmt.Errorf("bad ref: %s", path)
	}

	if root == "/http/" || root == "/https/" {
		fake := "example.com/foreign/layer" + "@" + digest
		dig, err := name.NewDigest(fake)
		if err != nil {
			return name.Digest{}, "", err
		}
		return dig, root + ref, nil
	}
	if root == "/cache/" {
		idx, ref, ok := strings.Cut(ref, "/")
		if !ok {
			return name.Digest{}, "", fmt.Errorf("strings.Cut(%q)", ref)
		}
		dig, err := name.NewDigest(ref)
		if err != nil {
			return name.Digest{}, "", err
		}
		return dig, idx, nil
	}

	dig, err := name.NewDigest(ref)
	if err != nil {
		return name.Digest{}, "", err
	}

	return dig, root + ref, nil
}

// Fetch blob from registry or URL.
func (h *handler) fetchBlob(w http.ResponseWriter, r *http.Request) (*sizeBlob, string, error) {
	path, root, err := splitFsURL(r.URL.Path)
	if err != nil {
		return nil, "", err
	}

	expectedSize := int64(0)
	qsize := r.URL.Query().Get("size")
	if qsize != "" {
		if sz, err := strconv.ParseInt(qsize, 10, 64); err != nil {
			log.Printf("wtf? %q size=%q", path, qsize)
		} else {
			expectedSize = sz
		}
	}

	chunks := strings.SplitN(path, "@", 2)
	if len(chunks) != 2 {
		return nil, "", fmt.Errorf("not enough chunks: %s", path)
	}
	// 71 = len("sha256:") + 64
	if len(chunks[1]) < 71 {
		return nil, "", fmt.Errorf("second chunk too short: %s", chunks[1])
	}

	digest := chunks[1][:71]

	ref := strings.Join([]string{chunks[0], digest}, "@")
	if ref == "" {
		return nil, "", fmt.Errorf("bad ref: %s", path)
	}

	if root == "/http/" || root == "/https/" {
		if debug {
			log.Printf("chunks[0]: %v", chunks[0])
		}

		u, err := url.PathUnescape(chunks[0])
		if err != nil {
			return nil, "", err
		}

		scheme := "https://"
		if root == "/http/" {
			scheme = "http://"
		}
		u = scheme + u
		log.Printf("GET %v", u)

		resp, err := http.Get(u)
		if err != nil {
			return nil, "", err
		}
		if resp.StatusCode == http.StatusOK {
			h, err := v1.NewHash(digest)
			if err != nil {
				return nil, "", err
			}
			checked, err := verify.ReadCloser(resp.Body, resp.ContentLength, h)
			if err != nil {
				return nil, "", err
			}
			size := expectedSize
			if size != 0 {
				if got := resp.ContentLength; got != -1 && got != size {
					log.Printf("GET %s unexpected size: got %d, want %d", u, got, expectedSize)
				}
			} else {
				size = resp.ContentLength
			}
			sb := &sizeBlob{checked, size}
			return sb, root + ref, nil
		}
		resp.Body.Close()
		log.Printf("GET %s failed: %s", u, resp.Status)
	}

	blobRef, err := name.NewDigest(ref)
	if err != nil {
		return nil, "", err
	}

	opts := h.remoteOptions(w, r, blobRef.Context().Name())
	l, err := remote.Layer(blobRef, opts...)
	if err != nil {
		return nil, "", err
	}

	rc, err := l.Compressed()
	if err != nil {
		return nil, "", err
	}

	size := expectedSize
	if size == 0 {
		size, err = l.Size()
		if err != nil {
			defer rc.Close()
			return nil, "", err
		}
	}
	sb := &sizeBlob{rc, size}
	return sb, root + ref, err
}

func (h *handler) jq(output *jsonOutputter, b []byte, r *http.Request, data *HeaderData) ([]byte, error) {
	jq, ok := r.URL.Query()["jq"]
	if !ok {
		data.JQ += " | jq ."
		return b, nil
	}

	var (
		err error
		exp string
	)

	exps := []string{data.JQ}

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

	data.JQ = strings.Join(exps, " | ")
	return b, nil
}

func getBlobQuery(r *http.Request) (string, bool) {
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

func splitFsURL(p string) (string, string, error) {
	for _, prefix := range []string{"/fs/", "/layers/", "/https/", "/http/", "/blob/", "/json/", "/cache/"} {
		if strings.HasPrefix(p, prefix) {
			return strings.TrimPrefix(p, prefix), prefix, nil
		}
	}

	return "", "", fmt.Errorf("unexpected path: %v", p)
}

// 5 MB.
const threshold = (1 << 20) * 5

func indexKey(prefix string, idx int) string {
	return fmt.Sprintf("%s.%d", prefix, idx)
}

func (h *handler) getIndex(ctx context.Context, prefix string) (soci.Index, error) {
	start := time.Now()
	defer func() {
		logs.Debug.Printf("getIndex(%q) (%s)", prefix, time.Since(start))
	}()
	return h.getIndexN(ctx, prefix, 0)
}

func (h *handler) getIndexN(ctx context.Context, prefix string, idx int) (index soci.Index, err error) {
	key := indexKey(prefix, idx)
	bs := &cacheSeeker{h.indexCache, key}

	var (
		toc  *soci.TOC
		size int64
	)
	// Avoid calling cache.Size if we can.
	if h.tocCache != nil {
		toc, err = h.tocCache.Get(ctx, key)
		if err != nil {
			logs.Debug.Printf("cache.Get(%q) = %v", key, err)
			defer func() {
				if err == nil {
					if err := h.tocCache.Put(ctx, key, index.TOC()); err != nil {
						logs.Debug.Printf("cache.Put(%q) = %v", key, err)
					}
				}
			}()
		} else {
			size = toc.Size
			logs.Debug.Printf("cache.Get(%q) = hit", key)
		}
	}

	// Handle in-memory index under a certain size.
	if size == 0 {
		size, err = h.indexCache.Size(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("indexCache.Size: %w", err)
		}
	}
	if size <= threshold {
		return soci.NewIndex(bs, toc, nil)
	}

	// Index is too big to hold in memory, fetch or create an index of the index.
	sub, err := h.getIndexN(ctx, prefix, idx+1)
	if err != nil {
		logs.Debug.Printf("getIndexN(%q, %d) = %v", prefix, idx+1, err)
		rc, err := h.indexCache.Reader(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("indexCache.Reader: %w", err)
		}
		sub, err = h.createIndex(ctx, rc, size, prefix, idx+1, "application/tar+gzip")
		if err != nil {
			return nil, fmt.Errorf("createIndex(%q, %d): %w", prefix, idx+1, err)
		}
		if sub == nil {
			return nil, fmt.Errorf("createIndex returned nil, not a tar.gz file")
		}
	}

	return soci.NewIndex(bs, toc, sub)
}
