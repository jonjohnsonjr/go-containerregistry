package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

var mt = flag.String("m", string(types.OCIImageIndex), "set the outer manifest mediaType (application/vnd.oci.image.index.v1+json | application/vnd.oci.image.manifest.v1+json)")
var dst = flag.String("t", "", "where to push the images")
var v = flag.Bool("v", false, "verbose")

func main() {
	flag.Parse()

	logs.Debug.Printf("-m=%s\n", *mt)
	logs.Debug.Printf("-t=%s\n", *dst)

	logs.Warn.SetOutput(os.Stderr)
	logs.Progress.SetOutput(os.Stderr)

	if *v {
		logs.Debug.SetOutput(os.Stderr)
	}

	if len(flag.Args()) < 2 || len(*dst) == 0 {
		flag.Usage()
		return
	}

	if err := run(flag.Arg(0), flag.Arg(1), *mt, *dst); err != nil {
		log.Fatal(err)
	}
}

func run(one, two string, mt string, repo string) error {
	inner, err := crane.Pull(one)
	if err != nil {
		return err
	}

	outer, err := crane.Pull(two)
	if err != nil {
		return err
	}

	inner, err = toOci(inner)
	if err != nil {
		return err
	}

	outer, err = toOci(outer)
	if err != nil {
		return err
	}

	w := &wrapper{
		inner: inner,
		outer: outer,
		mt:    types.MediaType(mt),
	}

	dst, err := name.NewRepository(repo)
	if err != nil {
		return err
	}

	if err := crane.Push(inner, dst.Tag("inner").String()); err != nil {
		return err
	}
	if err := crane.Push(outer, dst.Tag("outer").String()); err != nil {
		return err
	}

	logs.Progress.Printf("pushing to %s:%s with mediaType %q", dst, "monster", mt)
	if err := remote.Put(dst.Tag("monster"), w, remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		return err
	}

	// TODO
	// 1. Make both OCI.
	// 2. Push to repo
	// 3. Combine into index
	// 4. Push to dst

	return nil
}

func toOci(img v1.Image) (v1.Image, error) {
	layers, err := img.Layers()
	if err != nil {
		return nil, err
	}

	adds := []mutate.Addendum{}

	for _, layer := range layers {
		adds = append(adds, mutate.Addendum{
			Layer:     layer,
			MediaType: types.OCILayer,
		})
	}

	cf, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}
	cf.History = []v1.History{}
	cf.RootFS.DiffIDs = []v1.Hash{}

	oci, err := mutate.ConfigFile(empty.Image, cf)
	if err != nil {
		return nil, err
	}
	oci, err = mutate.Append(oci, adds...)
	if err != nil {
		return nil, err
	}
	oci = mutate.ConfigMediaType(oci, types.OCIConfigJSON)
	oci = mutate.MediaType(oci, types.OCIManifestSchema1)

	return oci, nil
}

type wrapper struct {
	inner v1.Image
	outer v1.Image
	mt    types.MediaType
}

type monster struct {
	SchemaVersion int64           `json:"schemaVersion"`
	Config        v1.Descriptor   `json:"config"`
	Layers        []v1.Descriptor `json:"layers"`
	Manifests     []v1.Descriptor `json:"manifests"`
}

func (w *wrapper) RawManifest() ([]byte, error) {
	m := monster{
		SchemaVersion: 2,
	}
	desc, err := partial.Descriptor(w.inner)
	if err != nil {
		return nil, err
	}
	om, err := w.outer.Manifest()
	if err != nil {
		return nil, err
	}

	// TODO: Configurable?
	desc.Platform = &v1.Platform{
		Architecture: "amd64",
		OS:           "linux",
	}
	m.Manifests = []v1.Descriptor{
		*desc,
	}
	m.Config = om.Config
	m.Layers = om.Layers
	return json.Marshal(m)
}

func (w *wrapper) MediaType() (types.MediaType, error) {
	return w.mt, nil
}
