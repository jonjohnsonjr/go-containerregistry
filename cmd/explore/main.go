package main

import (
	"archive/tar"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/google/go-containerregistry/pkg/v1/v1util"
)

const indexTemplate = `
<div style="font-family: monospace;">
{
	<div style="margin-left: 2em;">
	<div>
	"schemaVersion": {{.SchemaVersion}},
	</div>
	<div>
	"mediaType": "{{.MediaType}}",
	</div>
	<div>
	"manifests": [
	{{ range .Manifests }}
	<div style="margin-left: 2em;">
	{
		<div style="margin-left: 2em;">
		<div>
		"mediaType": "{{.MediaType}}",
		</div>
		<div>
		"size": {{.Size}},
		</div>
		<div>
		"digest": <a href="/?image={{$.Repo}}@{{.Digest}}">{{.Digest}}</a>,
		</div>
		{{ if .Platform }}
		{{ with .Platform }}
		<div>
		"platform": {
			<div style="margin-left: 2em;">
			<div>
			"architecture": "{{.Architecture}}",
			</div>
			<div>
			"os": "{{.OS}}",
			</div>
			{{ if .OSVersion }}
			<div>
			"os.version": "{{.OSVersion}}",
			</div>
			{{end}}
			{{ if .OSFeatures }}
			<div>
			"os.features": [
				<div style="margin-left: 2em;">
				{{range .OSFeatures}}
					<div>
					"{{.}}",
					</div>
				{{end}}
			</div>
			],
			</div>
			{{end}}
			{{ if .Variant }}
			<div>
			"variant": "{{.Variant}}"
			</div>
			{{end}}
			</div>
		}
		</div>
		{{end}}
		{{end}}
		</div>
	},
	</div>
	{{ end }}
	]
	</div>
	</div>
}
</div>
`

const manifestTemplate = `
<div style="font-family: monospace;">
{
	<div style="margin-left: 2em;">
	<div>
	"schemaVersion": {{.SchemaVersion}},
	</div>
	<div>
	"mediaType": "{{.MediaType}}",
	</div>
	<div>
	"config": {
		{{ with .Config }}
		<div style="margin-left: 2em;">
		<div>
		"mediaType": "{{.MediaType}}",
		</div>
		<div>
		"size": {{.Size}},
		</div>
		<div>
		"digest": <a href="/?config={{$.Repo}}@{{.Digest}}&image={{$.Image}}">{{.Digest}}</a>,
		</div>
		</div>
		{{ end }}
	}
	</div>
	<div>
	"layers": [
	{{ range .Layers }}
	<div style="margin-left: 2em;">
	{
		<div style="margin-left: 2em;">
		<div>
		"mediaType": "{{.MediaType}}",
		</div>
		<div>
		"size": {{.Size}},
		</div>
		<div>
		"digest": <a href="/?blob={{$.Repo}}@{{.Digest}}">{{.Digest}}</a>,
		</div>
		</div>
	},
	</div>
	{{ end }}
	]
	</div>
	</div>
}
</div>
`

type IndexData struct {
	Repo string
	v1.IndexManifest
}

type ManifestData struct {
	Repo  string
	Image string
	v1.Manifest
}

func handler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%v", r.URL.Query())

	if err := renderResponse(w, r); err != nil {
		fmt.Fprintf(w, "failed: %v", err)
	}
}

func main() {
	log.Print("Hello world sample started.")

	http.HandleFunc("/", handler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}

func renderResponse(w io.Writer, r *http.Request) error {
	qs := r.URL.Query()

	if blobs, ok := qs["blob"]; ok {
		return renderBlob(w, blobs[0])
	}

	if configs, ok := qs["config"]; ok {
		return renderConfig(w, configs[0])
	}

	images, ok := qs["image"]
	if !ok {
		return errors.New("expected 'image' in query string")
	}
	image := images[0]

	ref, err := name.ParseReference(image, name.WeakValidation)
	if err != nil {
		return err
	}
	desc, err := remote.Get(ref)
	if err != nil {
		return err
	}

	if desc.MediaType == types.DockerManifestList || desc.MediaType == types.OCIImageIndex {
		return renderIndex(w, desc, ref)
	} else if desc.MediaType == types.DockerManifestSchema2 || desc.MediaType == types.OCIManifestSchema1 {
		return renderImage(w, desc, ref)
	}

	return fmt.Errorf("unimplemented mediaType: %s", desc.MediaType)
}

func renderIndex(w io.Writer, desc *remote.Descriptor, ref name.Reference) error {
	index, err := desc.ImageIndex()
	if err != nil {
		return err
	}

	manifest, err := index.IndexManifest()
	if err != nil {
		return err
	}

	data := IndexData{
		Repo:          ref.Context().String(),
		IndexManifest: *manifest,
	}

	tmpl, err := template.New("indexTemplate").Parse(indexTemplate)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, data)
}

func renderImage(w io.Writer, desc *remote.Descriptor, ref name.Reference) error {
	img, err := desc.Image()
	if err != nil {
		return err
	}

	manifest, err := img.Manifest()
	if err != nil {
		return err
	}

	data := ManifestData{
		Repo:     ref.Context().String(),
		Image:    ref.String(),
		Manifest: *manifest,
	}

	tmpl, err := template.New("manifestTemplate").Parse(manifestTemplate)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, data)
}

func renderBlob(w io.Writer, ref string) error {
	blobRef, err := name.ParseReference(ref, name.StrictValidation)
	if err != nil {
		return err
	}

	blob, err := remote.Blob(blobRef)
	if err != nil {
		return err
	}

	zr, err := v1util.GunzipReadCloser(blob)
	if err != nil {
		return err
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		fmt.Fprintln(w, header.Name)
	}

	return nil
}

func renderConfig(w io.Writer, ref string) error {
	cfgRef, err := name.ParseReference(ref, name.StrictValidation)
	if err != nil {
		return err
	}

	blob, err := remote.Blob(cfgRef)
	if err != nil {
		return err
	}

	_, err = io.Copy(w, blob)
	return err
}
