package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func main() {
	logs.Debug.SetOutput(os.Stderr)
	if err := mainE(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func mainE(ctx context.Context) error {
	ref, err := name.ParseReference(os.Args[1])
	if err != nil {
		return err
	}

	opts := []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)}

	puller, err := remote.NewPuller(opts...)
	if err != nil {
		return fmt.Errorf("NewPuller: %w", err)
	}

	desc, err := puller.Get(ctx, ref)
	if err != nil {
		return fmt.Errorf("puller.Get: %w", err)
	}

	log.Printf("puller.Get:\n%s", string(desc.Manifest))

	pusher, err := remote.NewPusher(opts...)
	if err != nil {
		return fmt.Errorf("NewPusher; %w", err)
	}

	opts = append(opts, remote.Reuse(pusher))

	puller, err = remote.NewPuller(opts...)
	if err != nil {
		return fmt.Errorf("NewPuller(2): %w", err)
	}

	desc, err = puller.Get(ctx, ref)
	if err != nil {
		return fmt.Errorf("puller.Get(2): %w", err)
	}

	log.Printf("puller.Get(2):\n%s", string(desc.Manifest))

	return nil
}
