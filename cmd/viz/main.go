package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"path"
	"strconv"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

var port = flag.Int("port", 1338, "port to run registry on")

func main() {
	flag.Parse()
	fs := http.FileServer(http.Dir("."))
	http.Handle("/demo/", http.StripPrefix("/demo", fs))
	http.HandleFunc("/events/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL)
		index, err := strconv.Atoi(path.Base(r.URL.Path))
		if err != nil {
			return
		}
		if index > len(demo) {
			return
		}
		if err := json.NewEncoder(w).Encode(demo[index]); err != nil {
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}

type event struct {
	// Manifest| Blob | Upload
	Type string

	// Get, Head, Post, Patch, Put, Delete
	Method string

	// http.StatusOk, etc.
	Status int

	// Pushing by tag can create multiple objects.
	// TODO: How to represent upload finalization?
	Objects []object

	Repo       string
	Identifier string

	// Optional
	Progress *v1.Update
}

type object struct {
	Repo string

	// Tag | Manifest| Blob | Upload
	Kind string

	// Tag | Digest | UUID
	Identifier string

	Deps []object
}

type initialState struct {
	// Repo -> [Identifier -> object]
	Objects map[string]map[string]object
}

var demo = []event{{
	Type:       "Blob",
	Method:     "Head",
	Status:     404,
	Repo:       "ubuntu",
	Identifier: "sha256:abc",
}, {
	Type:       "Blob",
	Method:     "Head",
	Status:     404,
	Repo:       "ubuntu",
	Identifier: "sha256:123",
}, {
	Type:       "Upload",
	Method:     "Post",
	Status:     202,
	Repo:       "ubuntu",
	Identifier: "abc",
}, {
	Type:       "Upload",
	Method:     "Post",
	Status:     202,
	Repo:       "ubuntu",
	Identifier: "123",
}, {
	Type:       "Upload",
	Method:     "Patch",
	Status:     0,
	Repo:       "ubuntu",
	Identifier: "abc",
	Progress: &v1.Update{
		Total:    100,
		Complete: 0,
	},
}, {
	Type:       "Upload",
	Method:     "Patch",
	Status:     0,
	Repo:       "ubuntu",
	Identifier: "123",
	Progress: &v1.Update{
		Total:    200,
		Complete: 0,
	},
}, {
	Type:       "Upload",
	Method:     "Patch",
	Status:     202,
	Repo:       "ubuntu",
	Identifier: "abc",
	Progress: &v1.Update{
		Total:    100,
		Complete: 100,
	},
}, {
	Type:       "Upload",
	Method:     "Patch",
	Status:     0,
	Repo:       "ubuntu",
	Identifier: "123",
	Progress: &v1.Update{
		Total:    200,
		Complete: 100,
	},
}, {
	Type:       "Upload",
	Method:     "Put",
	Status:     201,
	Repo:       "ubuntu",
	Identifier: "123",
	Objects: []object{{
		Kind:       "Blob",
		Repo:       "ubuntu",
		Identifier: "sha256:123",
	}},
}, {
	Type:       "Upload",
	Method:     "Patch",
	Status:     202,
	Repo:       "ubuntu",
	Identifier: "123",
	Progress: &v1.Update{
		Total:    200,
		Complete: 200,
	},
}, {
	Type:       "Upload",
	Method:     "Put",
	Status:     201,
	Repo:       "ubuntu",
	Identifier: "abc",
	Objects: []object{{
		Kind:       "Blob",
		Repo:       "ubuntu",
		Identifier: "sha256:abc",
	}},
}, {
	Type:       "Manifest",
	Method:     "Put",
	Status:     201,
	Repo:       "ubuntu",
	Identifier: "sha256:def",
	Objects: []object{{
		Kind:       "Manifest",
		Repo:       "ubuntu",
		Identifier: "sha256:def",
		Deps: []object{{
			Kind:       "Blob",
			Repo:       "ubuntu",
			Identifier: "sha256:abc",
		}, {
			Kind:       "Blob",
			Repo:       "ubuntu",
			Identifier: "sha256:123",
		}},
	}},
}}
