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

	"cloud.google.com/go/storage"

	ogzip "compress/gzip"

	"github.com/google/go-containerregistry/internal/and"
	"github.com/google/go-containerregistry/internal/gzip"
	"github.com/google/go-containerregistry/internal/soci"
	"github.com/google/go-containerregistry/internal/verify"
	"github.com/google/go-containerregistry/internal/zstd"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	goog "github.com/google/go-containerregistry/pkg/v1/google"
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

	// Stupid hack because I'm too lazy to refactor.
	blobs map[*http.Request]*sizeBlob

	// digest -> remote.desc
	manifests map[string]*remote.Descriptor

	// reg.String() -> ping resp
	pings map[string]*transport.PingResp

	cache     cache
	treeCache cache

	sync.Mutex
	sawTags map[string][]string

	oauth *oauth2.Config
}

func (h *handler) remoteOptions(w http.ResponseWriter, r *http.Request, repo string) []remote.Option {
	ctx := r.Context()

	// TODO: Set timeout.
	// TODO: User agent.

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
				auth = goog.NewTokenSourceAuthenticator(ts)
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

// TODO: ugh
func (h *handler) googleOptions(w http.ResponseWriter, r *http.Request, repo string) []goog.Option {
	ctx := r.Context()

	opts := []goog.Option{}
	opts = append(opts, goog.WithContext(ctx))
	if repo == "mirror.gcr.io" {
		t := remote.DefaultTransport
		t = transport.NewRetry(t)
		t = transport.NewUserAgent(t, ua)
		if logs.Enabled(logs.Trace) {
			t = transport.NewTracer(t)
		}
		t = transport.Wrap(t)
		opts = append(opts, goog.WithTransport(t))
		return opts
	}
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
				auth = goog.NewTokenSourceAuthenticator(ts)
			}
		}
	}

	opts = append(opts, goog.WithAuth(auth))

	if t, err := h.transportFromCookie(w, r, repo, auth); err != nil {
		log.Printf("failed to get transport from cookie: %v", err)
	} else {
		opts = append(opts, goog.WithTransport(t))
	}

	return opts
}

type Option func(h *handler)

func WithRemote(opt []remote.Option) Option {
	return func(h *handler) {
		h.remote = opt
	}
}

// TODO: We can drop ~60ms by skipping the auth handshake.
func buildOciCache(cacheRepo string) (cache, error) {
	repo, err := name.NewRepository(cacheRepo)
	if err != nil {
		return nil, err
	}

	scopes := []string{repo.Scope(transport.PushScope)}

	auth := authn.Anonymous
	if isGoogle(repo.RegistryStr()) {
		auth, err = goog.Keychain.Resolve(repo)
		if err != nil {
			return nil, err
		}
	}
	t := remote.DefaultTransport
	t = transport.NewRetry(t)
	t = transport.NewUserAgent(t, ua)
	if logs.Enabled(logs.Trace) {
		t = transport.NewTracer(t)
	}
	t, err = transport.New(repo.Registry, auth, t, scopes)
	if err != nil {
		return nil, err
	}
	return &ociCache{repo, t}, nil
}

func buildGcsCache(bucket string) (cache, error) {
	client, err := storage.NewClient(context.Background())
	if err != nil {
		return nil, err
	}
	bkt := client.Bucket(bucket)

	return &gcsCache{client, bkt}, nil
}

func buildCache() cache {
	// TODO
	mc := &memCache{
		// 50 MB * 50 = 2.5GB reserved for cache.
		maxSize:  50 * (1 << 20),
		entryCap: 50,
	}
	return mc
	//caches := []cache{mc}

	//if cd := os.Getenv("CACHE_DIR"); cd != "" {
	//	logs.Debug.Printf("CACHE_DIR=%q", cd)
	//	cache := &dirCache{cd}
	//	caches = append(caches, cache)
	//} else if cb := os.Getenv("CACHE_BUCKET"); cb != "" {
	//	logs.Debug.Printf("CACHE_BUCKET=%q", cb)
	//	if cache, err := buildGcsCache(cb); err != nil {
	//		logs.Debug.Printf("buildGcsCache(): %v", err)
	//	} else {
	//		caches = append(caches, cache)
	//	}
	//} else if cr := os.Getenv("CACHE_REPO"); cr != "" {
	//	logs.Debug.Printf("CACHE_REPO=%q", cr)
	//	if cache, err := buildOciCache(cr); err != nil {
	//		logs.Debug.Printf("buildOciCache(): %v", err)
	//	} else {
	//		caches = append(caches, cache)
	//	}
	//}

	//return &multiCache{caches}
}

// TODO: dedupe above
func buildTreeCache() cache {
	caches := []cache{}

	if cd := os.Getenv("CACHE_DIR"); cd != "" {
		logs.Debug.Printf("CACHE_DIR=%q", cd)
		cache := &dirCache{cd}
		caches = append(caches, cache)
	} else if cb := os.Getenv("CACHE_BUCKET"); cb != "" {
		logs.Debug.Printf("CACHE_BUCKET=%q", cb)
		if cache, err := buildGcsCache(cb); err != nil {
			logs.Debug.Printf("buildGcsCache(): %v", err)
		} else {
			caches = append(caches, cache)
		}
	} else if cr := os.Getenv("CACHE_REPO"); cr != "" {
		logs.Debug.Printf("CACHE_REPO=%q", cr)
		if cache, err := buildOciCache(cr); err != nil {
			logs.Debug.Printf("buildOciCache(): %v", err)
		} else {
			caches = append(caches, cache)
		}
	}
	return &multiCache{caches}
}

func New(opts ...Option) http.Handler {
	h := handler{
		mux:       http.NewServeMux(),
		blobs:     map[*http.Request]*sizeBlob{},
		manifests: map[string]*remote.Descriptor{},
		pings:     map[string]*transport.PingResp{},
		sawTags:   map[string][]string{},
		cache:     buildCache(),
		treeCache: buildTreeCache(),
		oauth:     buildOauth(),
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

	// Just dumps the bytes.
	// Useful for looking at something with the wrong mediaType.
	h.mux.HandleFunc("/raw/", h.fsHandler)

	// Try to detect mediaType.
	h.mux.HandleFunc("/blob/", h.fsHandler)
	h.mux.HandleFunc("/cache/", h.treeHandler)

	// We know it's JSON.
	h.mux.HandleFunc("/json/", h.fsHandler)

	// Same as above but un-gzips.
	h.mux.HandleFunc("/gzip/", h.fsHandler)

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

func isGoogle(host string) bool {
	if host != "gcr.io" && !strings.HasSuffix(host, ".gcr.io") && !strings.HasSuffix(host, ".pkg.dev") && !strings.HasSuffix(host, ".google.com") {
		return false
	}
	return true
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

type CookieValue struct {
	Reg           string
	PingResp      *transport.PingResp
	Repo          string
	TokenResponse *transport.TokenResponse
}

func (h *handler) transportFromCookie(w http.ResponseWriter, r *http.Request, repo string, auth authn.Authenticator) (http.RoundTripper, error) {
	parsed, err := name.NewRepository(repo)
	if err != nil {
		return nil, err
	}
	scopes := []string{parsed.Scope(transport.PullScope)}
	reg := parsed.Registry

	var (
		pr  *transport.PingResp
		tok *transport.TokenResponse
	)
	if regCookie, err := r.Cookie("registry_token"); err == nil {
		b, err := base64.URLEncoding.DecodeString(regCookie.Value)
		if err != nil {
			return nil, err
		}
		var v CookieValue
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, err
		}
		if v.Reg == reg.String() {
			pr = v.PingResp
			if v.Repo == repo {
				tok = v.TokenResponse
			}
		}
	}

	t := remote.DefaultTransport
	t = transport.NewRetry(t)
	t = transport.NewUserAgent(t, ua)
	if logs.Enabled(logs.Trace) {
		t = transport.NewTracer(t)
	}

	if pr == nil {
		if cpr, ok := h.pings[reg.String()]; ok {
			if debug {
				log.Printf("cached ping: %v", cpr)
			}
			pr = cpr
		} else {
			if debug {
				log.Printf("pinging %s", reg.String())
			}
			pr, err = transport.Ping(r.Context(), reg, t)
			if err != nil {
				return nil, err
			}
			h.pings[reg.String()] = pr
		}
	}

	if tok == nil {
		if debug {
			log.Printf("getting token %s", reg.String())
		}
		t, tok, err = transport.NewBearer(r.Context(), pr, reg, auth, t, scopes)
		if err != nil {
			return nil, err
		}

		// Probably no auth needed.
		if tok == nil {
			return t, nil
		}

		// Clear this to make cookies smaller.
		tok.AccessToken = ""

		v := &CookieValue{
			Reg:           reg.String(),
			PingResp:      pr,
			Repo:          repo,
			TokenResponse: tok,
		}
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		cv := base64.URLEncoding.EncodeToString(b)
		cookie := &http.Cookie{
			Name:     "registry_token",
			Value:    cv,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}
		if tok.ExpiresIn == 0 {
			tok.ExpiresIn = 60
		}
		exp := time.Now().Add(time.Second * time.Duration(tok.ExpiresIn))
		cookie.Expires = exp
		http.SetCookie(w, cookie)
	} else {
		if debug {
			log.Printf("restoring bearer %s", reg.String())
		}
		t, err = transport.OldBearer(pr, tok, reg, auth, t, scopes)
		if err != nil {
			return nil, err
		}
	}

	return t, nil
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
	tags, err := goog.List(ref, h.googleOptions(w, r, repo)...)
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
	if logs.Enabled(logs.Trace) {
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

type Schema1History struct {
	V1Compatibility string `json:"v1Compatibility"`
}

type Schema1 struct {
	History []Schema1History `json:"history"`
}

type Config struct {
	Cmd []string `json:"Cmd"`
}

type Compat struct {
	ContainerConfig Config `json:"container_config"`
}

// TODO: Dedupe
func renderDockerfileSchema1(w io.Writer, b []byte) error {
	m := Schema1{}
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	args := []string{}
	for i := len(m.History) - 1; i >= 0; i-- {
		compat := m.History[i]
		var sb strings.Builder
		c := Compat{}
		if err := json.Unmarshal([]byte(compat.V1Compatibility), &c); err != nil {
			return err
		}

		cb := strings.Join(c.ContainerConfig.Cmd, " ")

		// Attempt to handle weird ARG stuff.
		maybe := strings.TrimSpace(strings.TrimPrefix(cb, "/bin/sh -c #(nop)"))
		if before, after, ok := strings.Cut(maybe, "ARG "); ok && before == "" {
			args = append(args, after)
		} else if strings.HasPrefix(cb, "|") {
			if _, cb, ok = strings.Cut(cb, " "); ok {
				for _, arg := range args {
					cb = strings.TrimSpace(strings.TrimPrefix(cb, arg))
				}

				// Hack around array syntax.
				if !strings.HasPrefix(cb, "/bin/sh -c ") {
					cb = "/bin/sh -c " + cb
				}
			}
		}
		if err := renderCreatedBy(&sb, []byte(cb)); err != nil {
			return err
		}
		if _, err := sb.Write([]byte("\n\n")); err != nil {
			return err
		}
		if _, err := w.Write([]byte(sb.String())); err != nil {
			return err
		}
	}
	return nil
}

func renderDockerfile(w io.Writer, b []byte) error {
	cf, err := v1.ParseConfigFile(bytes.NewReader(b))
	if err != nil {
		return err
	}

	args := []string{}
	for _, hist := range cf.History {
		var sb strings.Builder
		cb := hist.CreatedBy

		// Attempt to handle weird ARG stuff.
		maybe := strings.TrimSpace(strings.TrimPrefix(cb, "/bin/sh -c #(nop)"))
		if before, after, ok := strings.Cut(maybe, "ARG "); ok && before == "" {
			args = append(args, after)
		} else if strings.HasPrefix(cb, "|") {
			if _, cb, ok = strings.Cut(cb, " "); ok {
				for _, arg := range args {
					cb = strings.TrimSpace(strings.TrimPrefix(cb, arg))
				}

				// Hack around array syntax.
				if !strings.HasPrefix(cb, "/bin/sh -c ") {
					cb = "/bin/sh -c " + cb
				}
			}
		}
		if err := renderCreatedBy(&sb, []byte(cb)); err != nil {
			return err
		}
		if _, err := sb.Write([]byte("\n\n")); err != nil {
			return err
		}
		if _, err := w.Write([]byte(sb.String())); err != nil {
			return err
		}
	}
	return nil
}

const (
	winPrefix = `powershell -Command $ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';`
	linPrefix = `/bin/sh -c`
)

func renderCreatedBy(w io.Writer, b []byte) error {
	// Heuristically try to format this correctly.
	for _, prefix := range []string{linPrefix, winPrefix} {
		b = bytes.TrimPrefix(b, []byte(prefix+" #(nop)"))
		if bytes.HasPrefix(b, []byte(prefix)) {
			b = bytes.Replace(b, []byte(prefix), []byte("RUN"), 1)
		}
	}
	b = bytes.ReplaceAll(b, []byte(" \t"), []byte(" \\\n\t"))
	b = bytes.ReplaceAll(b, []byte("&&\t"), []byte("\\\n&&\t"))
	b = whitespaceRegex.ReplaceAllFunc(b, whitespaceRepl)
	b = bytes.TrimSpace(b)
	if bytes.HasPrefix(b, []byte("EXPOSE")) {
		// Turn the map version into the dockerfile version
		b = bytes.TrimSuffix(b, []byte("]"))
		b = bytes.Replace(b, []byte("map["), []byte(""), 1)
		b = bytes.ReplaceAll(b, []byte(":{}"), []byte(""))
	}
	if bytes.HasPrefix(b, []byte("|")) {
		if _, after, ok := bytes.Cut(b, []byte("/bin/sh -c")); ok {
			b = []byte("RUN")
			b = append(b, after...)
		}
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	return nil
}

func (h *handler) treeHandler(w http.ResponseWriter, r *http.Request) {
	if err := h.renderTree(w, r); err != nil {
		log.Printf("renderTree: %v", err)
		fmt.Fprintf(w, "failed: %s", html.EscapeString(err.Error()))
	}
}
func (h *handler) renderTree(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	idx := 0
	dig, idxs, err := h.getDigest(w, r)
	if err != nil {
		return err
	}
	if parsed, err := strconv.ParseInt(idxs, 10, 64); err != nil {
		logs.Debug.Printf("ParseInt(%q)", idxs)
	} else {
		idx = int(parsed)
	}
	key := treeKey(dig.Identifier(), idx)
	size, err := h.treeCache.Size(ctx, key)
	if err != nil {
		return fmt.Errorf("treeCache.Size: %w", err)
	}
	rc, err := h.treeCache.Reader(ctx, key)
	if err != nil {
		return fmt.Errorf("treeCache.Reader: %w", err)
	}
	h.blobs[r] = &sizeBlob{rc, size}
	fs, err := h.newLayerFS(w, r, false, nil)
	if err != nil {
		return err
	}
	fs.blobRef = dig.String()
	defer fs.Close()

	// Allow this to be cached for an hour.
	w.Header().Set("Cache-Control", "max-age=3600, immutable")

	http.FileServer(fs).ServeHTTP(w, r)
	return nil
}

// Render blob, either as just ungzipped bytes, or via http.FileServer.
func (h *handler) renderBlob(w http.ResponseWriter, r *http.Request) error {
	if strings.HasPrefix(r.URL.Path, "/json/") {
		return h.renderBlobJSON(w, r, "")
	}

	// Bit of a hack for tekton bundles...
	if strings.HasPrefix(r.URL.Path, "/gzip/") || strings.HasPrefix(r.URL.Path, "/raw/") {
		blob, _, err := h.fetchBlob(w, r)
		if err != nil {
			return err
		}

		var rc io.ReadCloser = blob
		if strings.HasPrefix(r.URL.Path, "/gzip/") {
			rc, err = gzip.UnzipReadCloser(blob)
			if err != nil {
				return err
			}
			defer rc.Close()
		}

		_, err = io.Copy(w, rc)
		return err
	}

	dig, ref, err := h.getDigest(w, r)
	if err != nil {
		return fmt.Errorf("getDigest: %w", err)
	}

	var (
		tree soci.Tree
	)
	if h.treeCache != nil {
		tree, err = h.getTree(r.Context(), dig.Identifier())
		if err != nil {
			logs.Debug.Printf("treeCache.Tree(%q) = %v", dig.Identifier(), err)
		} else {
			logs.Debug.Printf("treeCache hit: %s", dig.Identifier())
		}
	}

	foreign := strings.HasPrefix(ref, "/http/") || strings.HasPrefix(ref, "/https/")
	shouldIndex := tree == nil
	if tree != nil && tree.TOC() != nil {
		opts := []remote.Option{}
		if !foreign {
			// Skip the ping for foreign layers.
			opts = h.remoteOptions(w, r, dig.Context().Name())
		}

		opts = append(opts, remote.WithSize(tree.TOC().Csize))

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
				if logs.Enabled(logs.Trace) {
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
		fs := soci.FS(tree, blob, prefix, dig.String(), respTooBig)
		http.FileServer(http.FS(fs)).ServeHTTP(w, r)

		return nil
	}

	// Determine if this is actually a filesystem thing.
	blob, ref, err := h.fetchBlob(w, r)
	if err != nil {
		return err
	}
	size := blob.size
	var rc io.ReadCloser = blob

	ok, pr, err := gztarPeek(blob)
	if err != nil {
		log.Printf("gztarPeek(%q): %v", ref, err)
	}

	if ok {
		// TODO: Clean this up.
		// We are letting this fall through later so that in reset() we start indexing.
		logs.Debug.Printf("it is targz")
	} else {
		logs.Debug.Printf("Peeking gzip")
		ok, pr, err = gzip.Peek(pr)
		if err != nil {
			log.Printf("gzip.Peek(%q): %v", ref, err)
		}

		rc = &and.ReadCloser{Reader: pr, CloseFunc: blob.Close}
		if ok {
			logs.Debug.Printf("it is gzip")
			rc, err = gzip.UnzipReadCloser(rc)
			if err != nil {
				return err
			}
		} else {
			rc = &and.ReadCloser{Reader: pr, CloseFunc: blob.Close}
			logs.Debug.Printf("Peeking zstd")
			ok, pr, err = zstdPeek(pr)
			if err != nil {
				log.Printf("zstdPeek(%q): %v", ref, err)
			}
			if ok {
				shouldIndex = false
				logs.Debug.Printf("it is zstd")
				rc, err = zstd.UnzipReadCloser(rc)
				if err != nil {
					return err
				}
			}
		}
		logs.Debug.Printf("Peeking tar")
		ok, pr, err = tarPeek(rc)
	}
	if ok {
		logs.Debug.Printf("it is tar")
		// Cache this for layerFS.reset() so we don't have to re-fetch it.
		h.blobs[r] = &sizeBlob{&and.ReadCloser{Reader: pr, CloseFunc: rc.Close}, size}

		var cw io.WriteCloser
		if shouldIndex {
			ocw, err := h.treeCache.Writer(r.Context(), treeKey(dig.Identifier(), 0))
			if err != nil {
				logs.Debug.Printf("treeCache.Writer: %v", err)
			} else {
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
				cw = &and.WriteCloser{bw, flushClose}
			}
		}
		fs, err := h.newLayerFS(w, r, shouldIndex, cw)
		if err != nil {
			// TODO: Try to detect if we guessed wrong about /blobs/ vs /manifests/ and redirect?
			return err
		}
		fs.blobRef = dig.String()
		defer fs.Close()

		// Allow this to be cached for an hour.
		w.Header().Set("Cache-Control", "max-age=3600, immutable")

		http.FileServer(fs).ServeHTTP(w, r)

		// TODO: Make it so we can do this incrementally.
		if shouldIndex {
			if indexer, ok := fs.tr.(*soci.TreeIndexer); ok {
				logs.Debug.Printf("got tree indexer")
				for {
					// Make sure we hit the end.
					_, err := indexer.Next()
					if errors.Is(err, io.EOF) {
						break
					} else if err != nil {
						return err
					}
				}

				toc, err := indexer.TOC()
				if err != nil {
					return err
				}
				if h.cache != nil {
					key := treeKey(dig.Identifier(), 0)
					if err := h.cache.Put(r.Context(), key, toc); err != nil {
						logs.Debug.Printf("cache.Put(%q) = %v", key, err)
					}
				}
				logs.Debug.Printf("tree size: %d", indexer.Size())
			} else {
				logs.Debug.Printf("not tree indexer, got: %T", fs.tr)
			}
		}
		return nil
	}

	qs := r.URL.Query()
	mt := qs.Get("mt")
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

	seek := &sizeSeeker{pr, size, ref, nil, false}
	http.ServeContent(w, r, "", time.Time{}, seek)

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

		if digest.String() == emptyDigest {
			// TODO: Non-targz should fail gracefully.
			continue
		}

		g.Go(func() error {
			var (
				tree soci.Tree
				err  error
			)
			if h.treeCache != nil {
				tree, err = h.getTree(r.Context(), digest.String())
				if err != nil {
					logs.Debug.Printf("treeCache.Tree(%q) = %v", digest.String(), err)
				} else {
					logs.Debug.Printf("treeCache hit: %s", digest.String())
				}
			}
			if tree == nil {
				l, err := remote.Layer(layerRef)
				if err != nil {
					return err
				}
				rc, err := l.Compressed()
				if err != nil {
					return err
				}

				tree, err = h.createTree(r.Context(), rc, size, digest.String(), 0)
				if err != nil {
					return fmt.Errorf("createTree: %w", err)
				}
				if tree == nil {
					return nil
				}
			}

			fs, err := h.createFs(w, r, ref, layerRef, tree, size, urls, opts)
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
	mfs := soci.MultiFS(fss, prefix)

	// Allow this to be cached for an hour.
	w.Header().Set("Cache-Control", "max-age=3600, immutable")

	http.FileServer(http.FS(mfs)).ServeHTTP(w, r)

	return nil
}

func (h *handler) createTree(ctx context.Context, rc io.ReadCloser, size int64, prefix string, idx int) (soci.Tree, error) {
	key := treeKey(prefix, idx)
	if debug {
		logs.Debug.Printf("createTree(%q)", key, idx)
		start := time.Now()
		defer func() {
			log.Printf("createTree(%q) (%s)", key, time.Since(start))
		}()
	}
	ok, pr, err := gztarPeek(bufio.NewReaderSize(rc, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("peek: %w", err)
	}
	if !ok {
		logs.Debug.Printf("not targz")

		ok, pr, err = tarPeek(pr)
		if !ok {
			logs.Debug.Printf("not tar either")
			return nil, nil
		}
	}

	blob := &and.ReadCloser{Reader: pr, CloseFunc: rc.Close}

	ocw, err := h.treeCache.Writer(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("treeCache.Writer: %w", err)
	}

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

	indexer, err := soci.NewTreeIndexer(blob, cw, spanSize)
	if err != nil {
		return nil, fmt.Errorf("soci.NewTreeIndexer: %w", err)
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
	if h.cache != nil {
		if err := h.cache.Put(ctx, key, toc); err != nil {
			logs.Debug.Printf("cache.Put(%q) = %v", key, err)
		}
	}
	logs.Debug.Printf("tree size: %d", indexer.Size())

	if err := ocw.Close(); err != nil {
		return nil, fmt.Errorf("ocw.Close: %w", err)
	}

	return h.getTreeIndex(ctx, prefix, idx)
}

func (h *handler) createFs(w http.ResponseWriter, r *http.Request, ref string, dig name.Digest, tree soci.Tree, size int64, urls []string, opts []remote.Option) (*soci.SociFS, error) {
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
	fs := soci.FS(tree, blob, prefix, dig.String(), respTooBig)
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

	// The first layerFS.reset() will hit this.
	if rc, ok := h.blobs[r]; ok {
		delete(h.blobs, r)
		return rc, root + ref, err
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
	for _, prefix := range []string{"/fs/", "/layers/", "/https/", "/http/", "/gzip/", "/raw/", "/blob/", "/json/", "/cache/"} {
		if strings.HasPrefix(p, prefix) {
			return strings.TrimPrefix(p, prefix), prefix, nil
		}
	}

	return "", "", fmt.Errorf("unexpected path: %v", p)
}

type RedirectCookie struct {
	Digest string
	Url    string
}

// 5 MB.
const threshold = (1 << 20) * 5

func treeKey(prefix string, idx int) string {
	return fmt.Sprintf("%s.%d", prefix, idx)
}

func (h *handler) getTree(ctx context.Context, prefix string) (soci.Tree, error) {
	start := time.Now()
	defer func() {
		logs.Debug.Printf("getTree(%q) (%s)", prefix, time.Since(start))
	}()
	return h.getTreeIndex(ctx, prefix, 0)
}

func (h *handler) getTreeIndex(ctx context.Context, prefix string, idx int) (tree soci.Tree, err error) {
	key := treeKey(prefix, idx)
	bs := &cacheSeeker{h.treeCache, key}

	var (
		toc  *soci.TOC
		size int64
	)
	// Avoid calling cache.Size if we can.
	if h.cache != nil {
		toc, err = h.cache.Get(ctx, key)
		if err != nil {
			logs.Debug.Printf("cache.Get(%q) = %v", key, err)
			defer func() {
				if err == nil {
					if err := h.cache.Put(ctx, key, tree.TOC()); err != nil {
						logs.Debug.Printf("cache.Put(%q) = %v", key, err)
					}
				}
			}()
		} else {
			size = toc.Size
			logs.Debug.Printf("cache.Get(%q) = hit", key)
		}
	}

	// Handle in-memory tree under a certain size.
	if size == 0 {
		size, err = h.treeCache.Size(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("treeCache.Size: %w", err)
		}
	}
	if size <= threshold {
		return soci.NewTree(bs, toc, nil)
	}

	// Tree is too big to hold in memory, fetch or create an index of the index.
	sub, err := h.getTreeIndex(ctx, prefix, idx+1)
	if err != nil {
		logs.Debug.Printf("getTreeIndex(%q, %d) = %v", prefix, idx+1, err)
		rc, err := h.treeCache.Reader(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("treeCache.Reader: %w", err)
		}
		sub, err = h.createTree(ctx, rc, size, prefix, idx+1)
		if err != nil {
			return nil, fmt.Errorf("createTree(%q, %d): %w", prefix, idx+1, err)
		}
		if sub == nil {
			return nil, fmt.Errorf("createTree returned nil, not a tar.gz file")
		}
	}

	return soci.NewTree(bs, toc, sub)
}

type cacheSeeker struct {
	cache cache
	key   string
}

func (bs *cacheSeeker) Reader(ctx context.Context, off int64, end int64) (io.ReadCloser, error) {
	logs.Debug.Printf("cacheSeeker.Reader(%d, %d)", off, end)
	return bs.cache.RangeReader(ctx, bs.key, off, end-off)
}
