package main

import (
	"bufio"
	"log"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if err := process(line); err != nil {
			log.Fatal(err)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Println(err)
	}
}

func process(line string) error {
	ref, err := name.ParseReference(line)
	if err != nil {
		return fmt.Errorf("failed to parse %q: %v", line, err)
	}
	desc, err := remote.Get(ref)
	if err != nil {
		return err
	}
	switch desc.MediaType {
	case types.OCIImageIndex, types.DockerManifestList:
		ii, err := desc.ImageIndex()
		if err != nil {
			return err
		}

		if err := writeIndex(ref, ii); err != nil {
			return err
		}
	case types.OCIManifestSchema1, types.DockerManifestSchema2:
		img, err := desc.Image()
		if err != nil {
			return err
		}
		if err := write(ref, img); err != nil {
			return err
		}
	}
}

func write(ref name.Reference, img v1.Image) error {
}

func writeIndex(ref name.Reference, ii v1.ImageIndex) error {
}
