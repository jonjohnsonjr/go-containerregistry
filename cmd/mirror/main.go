package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

func main() {
	logs.Debug.SetOutput(os.Stderr)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	s := &http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: New(),
	}
	log.Fatal(s.ListenAndServe())
}

type regError struct {
	Status   int
	Code     string
	Message  string
	original error
}

func (r *regError) Write(resp http.ResponseWriter) error {
	if r.original != nil {
		if te, ok := r.original.(*transport.Error); ok {
			resp.WriteHeader(r.Status)
			_, err := io.Copy(resp, strings.NewReader(te.RawBody))
			return err
		}
	}
	resp.WriteHeader(r.Status)

	type err struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	type wrap struct {
		Errors []err `json:"errors"`
	}
	return json.NewEncoder(resp).Encode(wrap{
		Errors: []err{
			{
				Code:    r.Code,
				Message: r.Message,
			},
		},
	})
}

type registry struct {
	log *log.Logger
}

// https://docs.docker.com/registry/spec/api/#api-version-check
// https://github.com/opencontainers/distribution-spec/blob/master/spec.md#api-version-check
func (r *registry) v2(resp http.ResponseWriter, req *http.Request) *regError {
	if isBlob(req) {
		return r.handleBlobs(resp, req)
	}
	if isManifest(req) {
		return r.handleManifests(resp, req)
	}
	if isTags(req) {
		return r.handleTags(resp, req)
	}
	if isCatalog(req) {
		return r.handleCatalog(resp, req)
	}
	resp.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	if req.URL.Path != "/v2/" && req.URL.Path != "/v2" && req.URL.Path != "/" {
		return &regError{
			Status:  http.StatusNotFound,
			Code:    "METHOD_UNKNOWN",
			Message: "We don't understand your method + url",
		}
	}
	resp.WriteHeader(200)
	return nil
}

func (r *registry) root(resp http.ResponseWriter, req *http.Request) {
	if rerr := r.v2(resp, req); rerr != nil {
		r.log.Printf("%s %s %d %s %s", req.Method, req.URL, rerr.Status, rerr.Code, rerr.Message)
		if err := rerr.Write(resp); err != nil {
			r.log.Printf("err writing err: %v", err)
		}
		return
	}
	r.log.Printf("%s %s", req.Method, req.URL)
}

// New returns a handler which implements the docker registry protocol.
// It should be registered at the site root.
func New(opts ...Option) http.Handler {
	r := &registry{
		log: log.New(os.Stderr, "", log.LstdFlags),
	}
	for _, o := range opts {
		o(r)
	}
	return http.HandlerFunc(r.root)
}

// Option describes the available options
// for creating the registry.
type Option func(r *registry)

// Logger overrides the logger used to record requests to the registry.
func Logger(l *log.Logger) Option {
	return func(r *registry) {
		r.log = l
	}
}

func isManifest(req *http.Request) bool {
	elems := strings.Split(req.URL.Path, "/")
	elems = elems[1:]
	if len(elems) < 4 {
		return false
	}
	return elems[len(elems)-2] == "manifests"
}

func isTags(req *http.Request) bool {
	elems := strings.Split(req.URL.Path, "/")
	elems = elems[1:]
	if len(elems) < 4 {
		return false
	}
	return elems[len(elems)-2] == "tags"
}

func isCatalog(req *http.Request) bool {
	elems := strings.Split(req.URL.Path, "/")
	elems = elems[1:]
	if len(elems) < 2 {
		return false
	}

	return elems[len(elems)-1] == "_catalog"
}

func reqToRef(req *http.Request) (name.Reference, error) {
	elem := strings.Split(req.URL.Path, "/")
	elem = elem[1:]
	target := elem[len(elem)-1]
	repo := strings.Join(elem[1:len(elem)-2], "/")

	if strings.Contains(target, ":") {
		return name.ParseReference(repo + "@" + target)
	}
	return name.ParseReference(repo + ":" + target)
}

// https://github.com/opencontainers/distribution-spec/blob/master/spec.md#pulling-an-image-manifest
// https://github.com/opencontainers/distribution-spec/blob/master/spec.md#pushing-an-image
func (r *registry) handleManifests(resp http.ResponseWriter, req *http.Request) *regError {
	ref, err := reqToRef(req)
	if err != nil {
		return r.oops(req, err)
	}

	if req.Method == "GET" {
		// TODO: Head and check cache?
		// TODO: Handle digests separately?
		desc, err := remote.Get(ref)
		if err != nil {
			return r.oops(req, err)
		}

		resp.Header().Set("Docker-Content-Digest", desc.Digest.String())
		resp.Header().Set("Content-Type", string(desc.MediaType))
		resp.Header().Set("Content-Length", strconv.Itoa(int(desc.Size)))
		resp.WriteHeader(http.StatusOK)
		io.Copy(resp, bytes.NewReader(desc.Manifest))
		return nil
	}

	if req.Method == "HEAD" {
		desc, err := remote.Head(ref)
		if err != nil {
			return r.oops(req, err)
		}
		resp.Header().Set("Docker-Content-Digest", desc.Digest.String())
		resp.Header().Set("Content-Type", string(desc.MediaType))
		resp.Header().Set("Content-Length", strconv.Itoa(int(desc.Size)))
		resp.WriteHeader(http.StatusOK)
		return nil
	}

	return &regError{
		Status:  http.StatusBadRequest,
		Code:    "METHOD_UNKNOWN",
		Message: "We don't understand your method + url",
	}
}

func (r *registry) handleTags(resp http.ResponseWriter, req *http.Request) *regError {
	return &regError{
		Status:  http.StatusBadRequest,
		Code:    "METHOD_UNKNOWN",
		Message: "We don't understand your method + url",
	}
}

func (r *registry) handleCatalog(resp http.ResponseWriter, req *http.Request) *regError {
	return &regError{
		Status:  http.StatusBadRequest,
		Code:    "METHOD_UNKNOWN",
		Message: "We don't understand your method + url",
	}
}

func (r *registry) oops(req *http.Request, err error) *regError {
	r.log.Printf("%s %s: %v", req.Method, req.URL, err)
	return &regError{
		Status:   http.StatusInternalServerError,
		Code:     "UNKNOWN",
		Message:  "/shrug",
		original: err,
	}
}

// Returns whether this url should be handled by the blob handler
// This is complicated because blob is indicated by the trailing path, not the leading path.
// https://github.com/opencontainers/distribution-spec/blob/master/spec.md#pulling-a-layer
// https://github.com/opencontainers/distribution-spec/blob/master/spec.md#pushing-a-layer
func isBlob(req *http.Request) bool {
	elem := strings.Split(req.URL.Path, "/")
	elem = elem[1:]
	if elem[len(elem)-1] == "" {
		elem = elem[:len(elem)-1]
	}
	if len(elem) < 3 {
		return false
	}
	return elem[len(elem)-2] == "blobs" || (elem[len(elem)-3] == "blobs" &&
		elem[len(elem)-2] == "uploads")
}

func (r *registry) handleBlobs(resp http.ResponseWriter, req *http.Request) *regError {
	elem := strings.Split(req.URL.Path, "/")
	elem = elem[1:]
	if elem[len(elem)-1] == "" {
		elem = elem[:len(elem)-1]
	}
	// Must have a path of form /v2/{name}/blobs/{upload,sha256:}
	if len(elem) < 4 {
		return &regError{
			Status:  http.StatusBadRequest,
			Code:    "NAME_INVALID",
			Message: "blobs must be attached to a repo",
		}
	}

	ref, err := reqToRef(req)
	if err != nil {
		return r.oops(req, err)
	}

	t := http.DefaultTransport
	if logs.Enabled(logs.Debug) {
		t = transport.NewLogger(t)
	}

	tr, err := transport.NewWithContext(req.Context(), ref.Context().Registry, authn.Anonymous, t, []string{ref.Scope(transport.PullScope)})
	if err != nil {
		return r.oops(req, err)
	}

	if req.Method == "GET" || req.Method == "HEAD" {
		u := "https://" + ref.Context().RegistryStr() + req.URL.Path
		log.Printf("url=%q", u)
		req, err := http.NewRequest("HEAD", u, nil)
		if err != nil {
			return r.oops(req, err)
		}
		log.Printf("req=%v", req)
		res, err := tr.RoundTrip(req)
		if err != nil {
			return r.oops(req, err)
		}
		resp.Header().Set("Location", res.Header.Get("Location"))
		resp.WriteHeader(res.StatusCode)
		return nil
	}

	return &regError{
		Status:  http.StatusBadRequest,
		Code:    "METHOD_UNKNOWN",
		Message: "We don't understand your method + url",
	}
}
