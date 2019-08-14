package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/gorilla/mux"
)

func craneHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	cmd := vars["command"]
	arg := vars["arg"]
	command := fmt.Sprintf("crane %s %s", cmd, arg)
	log.Printf(command)
	if err := doCrane(w, cmd, arg); err != nil {
		fmt.Fprintf(w, "%s: %v", command, err)
	}
}

func doCrane(w http.ResponseWriter, cmd, arg string) error {
	switch cmd {
	case "ls":
		tags, err := crane.ListTags(arg)
		if err != nil {
			return err
		}
		for _, tag := range tags {
			fmt.Fprintln(w, tag)
		}
	case "manifest":
		m, err := crane.Manifest(arg)
		if err != nil {
			return err
		}
		_, err = io.Copy(w, bytes.NewReader(m))
		return err
	case "digest":
		d, err := crane.Digest(arg)
		if err != nil {
			return err
		}
		fmt.Fprint(w, d)
	case "config":
		c, err := crane.Config(arg)
		if err != nil {
			return err
		}
		_, err = io.Copy(w, bytes.NewReader(c))
		return err
	}
	return nil
}

func gcraneHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("gcrane")
}

func main() {
	log.Print("Hello world sample started.")

	// TODO: dispatch based on domain
	r := mux.NewRouter()
	r.HandleFunc("/{command}/{arg:.*}", craneHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.Handle("/", r)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}
