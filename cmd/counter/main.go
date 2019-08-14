package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func handler(w http.ResponseWriter, r *http.Request) {
	counter := os.Getenv("COUNTER")
	if counter == "" {
		counter = "0"
	}

	count, err := increment(w, counter)
	if err != nil {
		fmt.Fprintf(w, "something bad happened: %v", err)
		return
	}

	fmt.Fprintf(w, "\nthis image has been pulled %d times\n", count)
}

func increment(w http.ResponseWriter, counter string) (int, error) {
	count, err := strconv.Atoi(counter)
	if err != nil {
		return 0, fmt.Errorf("Couldn't parse counter: %v", err)
	}
	count++

	tag := os.Getenv("IMAGE")
	if tag == "" {
		return 0, fmt.Errorf("IMAGE was unset!")
	}

	ref, err := name.ParseReference(tag)
	if err != nil {
		return 0, err
	}

	kc, err := k8schain.NewInCluster(k8schain.Options{
		ServiceAccountName: "counter",
		ImagePullSecrets:   []string{"regcred"},
	})
	if err != nil {
		return 0, err
	}

	img, err := remote.Image(ref, remote.WithAuthFromKeychain(kc))
	if err != nil {
		return 0, err
	}

	prev, err := img.Digest()
	if err != nil {
		return 0, err
	}
	fmt.Fprintf(w, "This image: %s@%s\n", tag, prev.String())

	cf, err := img.ConfigFile()
	if err != nil {
		return 0, err
	}

	cfg := cf.Config
	for i, env := range cfg.Env {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			return 0, fmt.Errorf("weird env: %v", env)
		}
		if parts[0] == "COUNTER" {
			cfg.Env[i] = fmt.Sprintf("COUNTER=%d", count)
			break
		} else if parts[0] == "DIGEST" {
			cfg.Env[i] = fmt.Sprintf("DIGEST=%s", prev.String())
		}
	}
	if os.Getenv("COUNTER") == "" {
		cfg.Env = append(cfg.Env, fmt.Sprintf("COUNTER=%d", count))
	}
	if os.Getenv("DIGEST") == "" {
		cfg.Env = append(cfg.Env, fmt.Sprintf("DIGEST=%s", prev.String()))
	}

	img, err = mutate.Config(img, cfg)
	if err != nil {
		return 0, err
	}

	next, err := img.Digest()
	if err != nil {
		return 0, err
	}
	fmt.Fprintf(w, "Next image: %s@%s\n", tag, next.String())

	if err := remote.Write(ref, img, remote.WithAuthFromKeychain(kc)); err != nil {
		return 0, err
	}

	return count, nil
}

func main() {
	log.Print("Counter started.")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/", handler)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}
