package main

import (
	"archive/tar"
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
	qs := r.URL.Query()

	if blobs, ok := qs["blob"]; ok {
		blobRef, err := name.ParseReference(blobs[0], name.StrictValidation)
		if err != nil {
			log.Fatal(err)
		}

		blob, err := remote.Blob(blobRef)
		if err != nil {
			log.Fatal(err)
		}

		zr, err := v1util.GunzipReadCloser(blob)
		if err != nil {
			log.Fatal(err)
		}
		defer zr.Close()

		tr := tar.NewReader(zr)
		for {
			header, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Fatal(err)
			}
			fmt.Fprintln(w, header.Name)
		}
		return
	}

	if configs, ok := qs["config"]; ok {
		cfgRef, err := name.ParseReference(configs[0], name.StrictValidation)
		if err != nil {
			log.Fatal(err)
		}

		blob, err := remote.Blob(cfgRef)
		if err != nil {
			log.Fatal(err)
		}

		io.Copy(w, blob)
		return
	}

	images, ok := qs["image"]
	if !ok {
		return
	}
	image := images[0]

	ref, err := name.ParseReference(image, name.WeakValidation)
	if err != nil {
		log.Fatal(err)
	}
	desc, err := remote.Get(ref)
	if err != nil {
		log.Fatal(err)
	}

	if desc.MediaType == types.DockerManifestList {
		index, err := desc.ImageIndex()
		if err != nil {
			log.Fatal(err)
		}

		manifest, err := index.IndexManifest()
		if err != nil {
			log.Fatal(err)
		}

		data := IndexData{
			Repo:          ref.Context().String(),
			IndexManifest: *manifest,
		}

		tmpl, err := template.New("indexTemplate").Parse(indexTemplate)
		if err != nil {
			log.Fatal(err)
		}
		if err := tmpl.Execute(w, data); err != nil {
			log.Fatal(err)
		}
	} else if desc.MediaType == types.DockerManifestSchema2 {
		img, err := desc.Image()
		if err != nil {
			log.Fatal(err)
		}

		manifest, err := img.Manifest()
		if err != nil {
			log.Fatal(err)
		}

		data := ManifestData{
			Repo:     ref.Context().String(),
			Image:    ref.String(),
			Manifest: *manifest,
		}

		tmpl, err := template.New("manifestTemplate").Parse(manifestTemplate)
		if err != nil {
			log.Fatal(err)
		}
		if err := tmpl.Execute(w, data); err != nil {
			log.Fatal(err)
		}
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
