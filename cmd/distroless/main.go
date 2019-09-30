package main

import (
	"log"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage: %s <ref>", os.Args[0])
	}
	if err := Main(os.Args[1]); err != nil {
		log.Fatal(err)
	}
}

func Main(dst string) error {
	// Copied from the ubuntu image -- we could have whatever we want here,
	// assuming architecture doesn't affect the filesystem contents.
	platforms := []v1.Platform{{
		Architecture: "amd64",
		OS:           "linux",
	}, {
		Architecture: "arm",
		OS:           "linux",
		Variant:      "v7",
	}, {
		Architecture: "arm64",
		OS:           "linux",
		Variant:      "v8",
	}, {
		Architecture: "386",
		OS:           "linux",
	}, {
		Architecture: "ppc64le",
		OS:           "linux",
	}, {
		Architecture: "s90x",
		OS:           "linux",
	}}

	// This being static is important, given above.
	img, err := crane.Pull("gcr.io/distroless/static:latest")
	if err != nil {
		return err
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return err
	}

	adds := []mutate.IndexAddendum{}
	for _, p := range platforms {
		// Update the config file to contain the right os/arch.
		cf := cf.DeepCopy()
		cf.Architecture = p.Architecture
		cf.OS = p.OS

		img, err = mutate.ConfigFile(img, cf)
		if err != nil {
			return err
		}

		// We need the "platform" field in the manifest list.
		p := p
		adds = append(adds, mutate.IndexAddendum{
			Descriptor: v1.Descriptor{
				Platform: &p,
			},
			Add: img,
		})
	}

	// Create a manifest list that points to the images we created.
	idx := mutate.AppendManifests(empty.Index, adds...)

	// Push it to args[1].
	ref, err := name.ParseReference(dst)
	if err != nil {
		return err
	}
	return remote.WriteIndex(ref, idx, remote.WithAuthFromKeychain(authn.DefaultKeychain))
}
