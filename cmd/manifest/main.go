package main

import (
	"log"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// First arg (os.Args[1]) is where we're going to push the image index,
// the rest are image references that we'll stitch together.
//
// This is similar to `crane append` but for manifest lists.
func main() {
	if len(os.Args) < 2 {
		log.Fatalf("not enough args")
	}

	if err := create(os.Args); err != nil {
		log.Fatal(err)
	}
}

func create(args []string) error {
	ref, err := name.ParseReference(args[1])
	if err != nil {
		return err
	}

	var idx v1.ImageIndex = empty.Index

	for _, r := range args[2:] {
		ref, err := name.ParseReference(r)
		if err != nil {
			return err
		}

		log.Printf("pulling %v", ref)
		img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
		if err != nil {
			return err
		}
		cf, err := img.ConfigFile()
		if err != nil {
			return err
		}

		platform := &v1.Platform{
			OS:           cf.OS,
			Architecture: cf.Architecture,
		}
		if cf.OSVersion != "" {
			platform.OSVersion = cf.OSVersion
		}

		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
			Add: img,
			Descriptor: v1.Descriptor{
				Platform: platform,
			},
		})

		// GCR doesn't like mixing OCI/Docker media types.
		idx = mutate.IndexMediaType(idx, types.DockerManifestList)
	}

	log.Printf("pushing to %v", ref)
	return remote.WriteIndex(ref, idx, remote.WithAuthFromKeychain(authn.DefaultKeychain))
}
