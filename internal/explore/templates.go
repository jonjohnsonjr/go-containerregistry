// Copyright 2021 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package explore

import (
	"text/template"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

var (
	bodyTmpl *template.Template
	repoTmpl *template.Template
)

func init() {
	bodyTmpl = template.Must(template.New("bodyTemplate").Parse(bodyTemplate))
	repoTmpl = template.Must(template.New("repoTemplate").Parse(repoTemplate))
}

const (
	landingPage = `
<html>
<body>
<head>
<style>
.mt:hover {
	text-decoration: underline;
}

.mt {
  color: inherit;
	text-decoration: inherit;
}
</style>
</head>
<h2>explore.<a class="mt" href="https://github.com/google/go-containerregistry">ggcr</a>.dev</h2>
<p>
This janky tool allows you to <em>explore</em> the contents of a registry interactively.
</p>
<p>
You can even drill down into layers to explore the filesystem.
</p>
<p>
Enter a <strong>public</strong> image, e.g. <tt>"ubuntu:latest"</tt>:
</p>
<form action="/" method="GET">
<input type="text" name="image" value="ubuntu:latest"/>
<input type="submit" />
</form>
<p>
<p>
Enter a <strong>public</strong> repository, e.g. <tt>"ubuntu"</tt>:
</p>
<form action="/" method="GET">
<input type="text" name="repo" value="ubuntu"/>
<input type="submit" />
</form>
</body>
</html>
`
	repoTemplate = `
<html>
<body>
<head>
<style>
body {
	font-family: monospace;
}
</style>
</head>
<h2>{{.Name}}</h2>
<div>
<ul>
{{range .Tags}}<li><a href="?image={{$.Name}}:{{.}}">{{.}}</a></li>{{end}}
</ul>
</div>
</body>
</html>
`

	header = `
<html>
<head>
<style>
.mt:hover {
	text-decoration: underline;
}

.mt {
  color: inherit;
	text-decoration: inherit;
}

body {
	font-family: monospace;
}

.indent {
  margin-left: 2em;
}
</style>
</head>
`

	bodyTemplate = `
<body>
<div>
<h2>{{.Reference}}{{ if .CosignTag }} (<a href="?image={{.Repo}}:{{.CosignTag}}">cosign</a>){{end}}</h2>
Docker-Content-Digest: {{.Descriptor.Digest}}<br>
Content-Length: {{.Descriptor.Size}}<br>
Content-Type: {{.Descriptor.MediaType}}<br>
</div>
<hr>
`

	footer = `
</body>
</html>
`
)

type RepositoryData struct {
	Name string
	Tags []string
}

type HeaderData struct {
	Repo       string
	Image      string
	CosignTag  string
	Reference  name.Reference
	Descriptor *remote.Descriptor
}

// Cosign simple signing stuff.
// TODO: Maybe just remove this?

type SimpleSigning struct {
	Critical Critical
	Optional map[string]string
}

type Critical struct {
	Identity Identity
	Image    Image
	Type     string
}

type Identity struct {
	DockerReference string `json:"docker-reference"`
}

type Image struct {
	DockerManifestDigest string `json:"Docker-manifest-digest"`
}
