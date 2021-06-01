package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/mirror"
)

func main() {
	logs.Debug.SetOutput(os.Stderr)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	s := &http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: mirror.New(),
	}
	log.Fatal(s.ListenAndServe())
}
