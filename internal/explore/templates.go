// Copyright 2021 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	headerTmpl *template.Template
	bodyTmpl   *template.Template
	repoTmpl   *template.Template
	oauthTmpl  *template.Template
)

func init() {
	headerTmpl = template.Must(template.New("headerTemplate").Parse(headerTemplate))
	bodyTmpl = template.Must(template.New("bodyTemplate").Parse(bodyTemplate))
	repoTmpl = template.Must(template.New("repoTemplate").Parse(repoTemplate))
	oauthTmpl = template.Must(template.New("oauthTemplate").Parse(oauthTemplate))
}

const (
	landingPage = `
<html>
<body>
<head>
<title>explore.ggcr.dev</title>
<link rel="icon" href="favicon.svg">
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

	oauthTemplate = `
<html>
<body>
<head>
<title>explore.ggcr.dev</title>
<link rel="icon" href="favicon.svg">
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
It looks like we encountered an auth error:
</p>
<code>
{{.Error}}
</code>
<p>
I currently can't support oauth for non-Googlers (sorry), but if you're a Googler and you trust <a class="mt" href="https://github.com/jonjohnsonjr">me</a>, click <a href="{{.Redirect}}">here</a>.
</p>
</body>
</html>
`
	repoTemplate = `
<html>
<body>
<head>
<title>{{.Name}}</title>
<link rel="icon" href="favicon.svg">
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

	headerTemplate = `
<html>
<head>
<title>{{.Title}}</title>
<link rel="icon" href="favicon.svg">
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
<hr>{{ if .JQ }}
<h4>{{.JQ}}</h4>
<hr>
{{ end }}
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

type OauthData struct {
	Error    string
	Redirect string
}

type TitleData struct {
	Title string
}

type HeaderData struct {
	Repo       string
	Image      string
	CosignTag  string
	JQ         string
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
