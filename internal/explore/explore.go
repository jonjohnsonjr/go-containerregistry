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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/internal/and"
	"github.com/google/go-containerregistry/internal/gzip"
	"github.com/google/go-containerregistry/internal/verify"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	goog "github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// We should not buffer blobs greater than 1MB
const tooBig = 2 << 20
const ua = "explore.ggcr.dev (jonjohnson at google dot com, if this is breaking you)"

type handler struct {
	mux    *http.ServeMux
	remote []remote.Option

	// Stupid hack because I'm too lazy to refactor.
	blobs map[*http.Request]*sizeBlob

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
			ts := h.oauth.TokenSource(r.Context(), tok)
			auth = goog.NewTokenSourceAuthenticator(ts)

		}
	}

	opts = append(opts, remote.WithAuth(auth))

	if t, err := h.transportFromCookie(w, r, repo, auth); err != nil {
		log.Printf("failed to get transport from cookie: %v", err)
	} else {
		log.Printf("restored bearer transport")
		opts = append(opts, remote.WithTransport(t))
	}

	return opts
}

type Option func(h *handler)

func WithRemote(opt []remote.Option) Option {
	return func(h *handler) {
		h.remote = opt
	}
}

func New(opts ...Option) http.Handler {
	conf := &oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		RedirectURL:  "https://explore.ggcr.dev/oauth",
		Scopes: []string{
			"https://www.googleapis.com/auth/cloud-platform.read-only",
		},
		Endpoint: google.Endpoint,
	}

	h := handler{
		mux:   http.NewServeMux(),
		blobs: map[*http.Request]*sizeBlob{},
		oauth: conf,
	}

	for _, opt := range opts {
		opt(&h)
	}

	h.mux.HandleFunc("/", h.root)
	h.mux.HandleFunc("/fs/", h.fsHandler)

	// Janky workaround for downloading via the "urls" field.
	h.mux.HandleFunc("/http/", h.fsHandler)
	h.mux.HandleFunc("/https/", h.fsHandler)

	// Just dumps the bytes.
	// Useful for looking at something with the wrong mediaType.
	h.mux.HandleFunc("/raw/", h.fsHandler)

	// Try to detect mediaType.
	h.mux.HandleFunc("/blob/", h.fsHandler)

	// We know it's JSON.
	h.mux.HandleFunc("/json/", h.fsHandler)

	// Same as above but un-gzips.
	h.mux.HandleFunc("/gzip/", h.fsHandler)

	h.mux.HandleFunc("/oauth", h.oauthHandler)

	return &h
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%v", r.URL)

	h.mux.ServeHTTP(w, r)
}

// Like http.Handler, but with error handling.
func (h *handler) root(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/favicon.svg" {
		http.ServeFile(w, r, filepath.Join(os.Getenv("KO_DATA_PATH"), "favicon.svg"))
		return
	}
	if err := h.renderResponse(w, r); err != nil {
		if err := h.handleOauth(w, r, err); err != nil {
			fmt.Fprintf(w, "failed: %v", err)
		}
	}
}

func isGoogle(host string) bool {
	if host != "gcr.io" && !strings.HasSuffix(host, ".gcr.io") && !strings.HasSuffix(host, ".pkg.dev") && !strings.HasSuffix(host, ".google.com") {
		return false
	}
	return true
}

func (h *handler) oauthHandler(w http.ResponseWriter, r *http.Request) {
	qs := r.URL.Query()
	code := qs.Get("code")
	tok, err := h.oauth.Exchange(r.Context(), code)
	if err != nil {
		log.Printf("Exchange: %v", err)
		fmt.Fprintf(w, "failed: %v", err)
		return
	}
	log.Printf("tok = %v", tok)

	state := qs.Get("state")
	u, err := url.ParseRequestURI(state)
	if err != nil {
		log.Printf("ParseRequestURI: %v", err)
		fmt.Fprintf(w, "failed: %v", err)
		return
	}
	if tok.AccessToken != "" {
		cookie := &http.Cookie{
			Name:     "access_token",
			Value:    tok.AccessToken,
			Expires:  tok.Expiry,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		}
		http.SetCookie(w, cookie)
	}
	if tok.RefreshToken != "" {
		cookie := &http.Cookie{
			Name:     "refresh_token",
			Value:    tok.RefreshToken,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		}
		http.SetCookie(w, cookie)
	}

	http.Redirect(w, r, u.String(), http.StatusFound)
}

// Like http.Handler, but with error handling.
func (h *handler) fsHandler(w http.ResponseWriter, r *http.Request) {
	if err := h.renderBlob(w, r); err != nil {
		if err := h.handleOauth(w, r, err); err != nil {
			fmt.Fprintf(w, "failed: %v", err)
		}
	}
}

func (h *handler) handleOauth(w http.ResponseWriter, r *http.Request, err error) error {
	var terr *transport.Error
	if !errors.As(err, &terr) {
		return err
	}
	if !isGoogle(terr.Request.URL.Host) {
		return err
	}
	if terr.StatusCode != http.StatusForbidden && terr.StatusCode != http.StatusUnauthorized {
		return err
	}

	data := OauthData{
		Error:    err.Error(),
		Redirect: h.oauth.AuthCodeURL(r.URL.String()),
	}

	if err := oauthTmpl.Execute(w, data); err != nil {
		return fmt.Errorf("failed to render oauth page: %w", err)
	}
	return nil
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
	t = transport.NewLogger(t)
	t = transport.NewRetry(t)
	t = transport.NewUserAgent(t, ua)

	if pr == nil {
		pr, err = transport.Ping(r.Context(), reg, t)
		if err != nil {
			return nil, err
		}
	}

	if tok == nil {
		t, tok, err = transport.NewBearer(r.Context(), pr, reg, auth, t, scopes)
		if err != nil {
			return nil, err
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
			SameSite: http.SameSiteStrictMode,
		}
		if tok.ExpiresIn == 0 {
			tok.ExpiresIn = 60
		}
		exp := time.Now().Add(time.Second * time.Duration(tok.ExpiresIn))
		cookie.Expires = exp
		http.SetCookie(w, cookie)
	} else {
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
	_, err := io.Copy(w, strings.NewReader(landingPage))
	return err
}

// Render repo with tags linking to images.
func (h *handler) renderRepo(w http.ResponseWriter, r *http.Request, repo string) error {
	ref, err := name.NewRepository(repo)
	if err != nil {
		return err
	}

	tags, err := remote.List(ref, h.remoteOptions(w, r, repo)...)
	if err != nil {
		return err
	}

	data := RepositoryData{
		Name: ref.String(),
		Tags: tags,
	}

	return repoTmpl.Execute(w, data)
}

// Render manifests with links to blobs, manifests, etc.
func (h *handler) renderManifest(w http.ResponseWriter, r *http.Request, image string) error {
	qs := r.URL.Query()

	ref, err := name.ParseReference(image, name.WeakValidation)
	if err != nil {
		return err
	}
	opts := h.remoteOptions(w, r, ref.Context().Name())
	d, err := remote.Head(ref, opts...)
	if err != nil {
		return err
	}
	if d.Size > tooBig {
		return fmt.Errorf("manifest %s too big: %d", ref, d.Size)
	}
	desc, err := remote.Get(ref, opts...)
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
		if _, err := remote.Head(cosignRef, opts...); err != nil {
			log.Printf("remote.Head(%q): %v", cosignRef.String(), err)
		} else {
			data.CosignTag = cosignRef.Identifier()
		}
	}

	if _, ok := ref.(name.Digest); ok {
		// Allow this to be cached for an hour.
		w.Header().Set("Cache-Control", "max-age=3600, immutable")
	}

	if err := headerTmpl.Execute(w, TitleData{image}); err != nil {
		return err
	}

	output := &jsonOutputter{
		w:     w,
		u:     r.URL,
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

	if err := bodyTmpl.Execute(w, data); err != nil {
		return err
	}

	if r.URL.Query().Get("render") == "raw" {
		fmt.Fprintf(w, "<pre>")
		if _, err := w.Write(b); err != nil {
			return err
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

		l, err := remote.Layer(dig, h.remoteOptions(w, r, dig.Context().Name())...)
		if err != nil {
			return err
		}
		size, err = l.Size()
		if err != nil {
			log.Printf("layer %s Size(): %v", ref, err)
		} else if size > tooBig {
			return fmt.Errorf("layer %s too big: %d", ref, size)
		}
		blob, err = l.Compressed()
		if err != nil {
			return err
		}
	} else {
		fetched, prefix, err := h.fetchBlob(w, r)
		if err != nil {
			return err
		}
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
	defer blob.Close()

	// Allow this to be cached for an hour.
	w.Header().Set("Cache-Control", "max-age=3600, immutable")

	if err := headerTmpl.Execute(w, TitleData{blobRef}); err != nil {
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

	// TODO: Can we do this in a streaming way?
	b, err := ioutil.ReadAll(io.LimitReader(blob, tooBig))
	if err != nil {
		return err
	}

	if pt := r.URL.Query().Get("payloadType"); pt != "" {
		dsse := DSSE{}
		if err := json.Unmarshal(b, &dsse); err != nil {
			return err
		}
		b = dsse.Payload
	}
	if err := renderJSON(output, b); err != nil {
		return err
	}

	fmt.Fprintf(w, footer)

	return nil
}

// Render blob, either as just ungzipped bytes, or via http.FileServer.
func (h *handler) renderBlob(w http.ResponseWriter, r *http.Request) error {
	log.Printf("%v", r.URL)

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

	// Determine if this is actually a filesystem thing.
	blob, ref, err := h.fetchBlob(w, r)
	if err != nil {
		return err
	}
	size := blob.size
	var rc io.ReadCloser = blob
	ok, pr, err := gzip.Peek(blob)
	if err != nil {
		log.Printf("render(%q): %v", ref, err)
	}

	rc = &and.ReadCloser{Reader: pr, CloseFunc: blob.Close}
	if ok {
		log.Printf("it is gzip")
		rc, err = gzip.UnzipReadCloser(rc)
		if err != nil {
			return err
		}
	}
	ok, pr, err = tarPeek(rc)
	if ok {
		log.Printf("it is tar")
		h.blobs[r] = &sizeBlob{&and.ReadCloser{Reader: pr, CloseFunc: rc.Close}, size}

		fs, err := h.newLayerFS(w, r)
		if err != nil {
			// TODO: Try to detect if we guessed wrong about /blobs/ vs /manifests/ and redirect?
			return err
		}
		defer fs.Close()

		// Allow this to be cached for an hour.
		w.Header().Set("Cache-Control", "max-age=3600, immutable")

		http.FileServer(fs).ServeHTTP(w, r)
		return nil
	}

	qs := r.URL.Query()
	mt := qs.Get("mt")
	if mt != "" {
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

	log.Printf("it is neither")

	// Allow this to be cached for an hour.
	w.Header().Set("Cache-Control", "max-age=3600, immutable")

	seek := &sizeSeeker{pr, size, ref, nil, false}
	http.ServeContent(w, r, "", time.Time{}, seek)

	return nil
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

	chunks := strings.Split(path, "@")
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

	if rc, ok := h.blobs[r]; ok {
		delete(h.blobs, r)
		return rc, root + ref, err
	}

	if root == "/http/" || root == "/https/" {
		log.Printf("chunks[0]: %v", chunks[0])

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

	l, err := remote.Layer(blobRef, h.remoteOptions(w, r, blobRef.Context().Name())...)
	if err != nil {
		return nil, "", err
	}
	size := expectedSize
	if size == 0 {
		size, err = l.Size()
		if err != nil {
			return nil, "", err
		}
	}
	rc, err := l.Compressed()
	if err != nil {
		return nil, "", err
	}
	sb := &sizeBlob{rc, size}
	return sb, root + ref, err
}

func (h *handler) jq(output *jsonOutputter, b []byte, r *http.Request, data *HeaderData) ([]byte, error) {
	jq, ok := r.URL.Query()["jq"]
	if !ok {
		return b, nil
	}

	var (
		err error
		exp string
	)

	exps := []string{"crane manifest " + data.Reference.String()}

	for _, j := range jq {
		log.Printf("j = %s", j)
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

func munge(ref name.Reference) (name.Reference, error) {
	munged := strings.ReplaceAll(ref.String(), "@sha256:", "@sha256-")
	munged = strings.ReplaceAll(munged, "@", ":")
	munged = munged + ".cosign"
	return name.ParseReference(munged)
}

func splitFsURL(p string) (string, string, error) {
	for _, prefix := range []string{"/fs/", "/https/", "/http/", "/gzip/", "/raw/", "/blob/", "/json/"} {
		if strings.HasPrefix(p, prefix) {
			return strings.TrimPrefix(p, prefix), prefix, nil
		}
	}

	return "", "", fmt.Errorf("unexpected path: %v", p)
}

// Pretends to implement Seek because ServeContent only cares about checking
// for the size by calling Seek(0, io.SeekEnd)
type sizeSeeker struct {
	rc     io.Reader
	size   int64
	debug  string
	buf    *bufio.Reader
	seeked bool
}

func (s *sizeSeeker) Seek(offset int64, whence int) (int64, error) {
	if debug {
		log.Printf("sizeSeeker.Seek(%d, %d)", offset, whence)
	}
	s.seeked = true
	if offset == 0 && whence == io.SeekEnd {
		return s.size, nil
	}
	if offset == 0 && whence == io.SeekStart {
		return 0, nil
	}

	return 0, fmt.Errorf("ServeContent(%q): Seek(%d, %d)", s.debug, offset, whence)
}

func (s *sizeSeeker) Read(p []byte) (int, error) {
	if debug {
		log.Printf("sizeSeeker.Read(%d)", len(p))
	}
	// Handle first read.
	if s.buf == nil {
		if debug {
			log.Println("first read")
		}
		if len(p) <= bufferLen {
			s.buf = bufio.NewReaderSize(s.rc, bufferLen)
		} else {
			s.buf = bufio.NewReaderSize(s.rc, len(p))
		}

		// Currently, http will sniff before it seeks for size. If we haven't seen
		// a Read() but have seen a Seek already, that means we shouldn't peek.
		if !s.seeked {
			// Peek to handle the first content sniff.
			b, err := s.buf.Peek(len(p))
			if err != nil {
				if err == io.EOF {
					return bytes.NewReader(b).Read(p)
				} else {
					return 0, err
				}
			}
			return bytes.NewReader(b).Read(p)
		}
	}

	// TODO: We assume they will always sniff then reset.
	n, err := s.buf.Read(p)
	if debug {
		log.Printf("sizeSeeker.Read(%d): (%d, %v)", len(p), n, err)
	}
	return n, err
}

type sizeBlob struct {
	io.ReadCloser
	size int64
}

func (s *sizeBlob) Size() (int64, error) {
	if debug {
		log.Printf("sizeBlob.Size()")
	}
	return s.size, nil
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

type DSSE struct {
	PayloadType string `json:"payloadType"`
	Payload     []byte `json:"payload"`
}
