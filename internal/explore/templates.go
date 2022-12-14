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

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

var (
	headerTmpl *template.Template
	bodyTmpl   *template.Template
	oauthTmpl  *template.Template
)

func init() {
	headerTmpl = template.Must(template.New("headerTemplate").Parse(headerTemplate))
	bodyTmpl = template.Must(template.New("bodyTemplate").Parse(bodyTemplate))
	oauthTmpl = template.Must(template.New("oauthTemplate").Parse(oauthTemplate))
}

const (
	landingPage = `
<html>
<body>
<head>
<title>explore.ggcr.dev</title>
<link rel="icon" href="/favicon.svg">
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
<link rel="icon" href="/favicon.svg">
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

	headerTemplate = `
<html>
<head>
<title>{{.Title}}</title>
<link rel="icon" href="/favicon.svg">
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
{{ if .Up }}
<h2><a class="mt" href="?repo={{.Up.Parent}}">{{.Up.Parent}}</a>{{.Up.Separator}}<a class="mt" href="{{.Handler}}{{.Reference}}{{if .EscapedMediaType}}&mt={{.EscapedMediaType}}{{end}}">{{.Up.Child}}</a>{{ range .CosignTags }} (<a href="?image={{$.Repo}}:{{.Tag}}">{{.Short}}</a>){{end}}</h2>
{{ else }}
<h2>{{.Reference}}{{ range .CosignTags }} (<a href="?image={{$.Repo}}:{{.Tag}}">{{.Short}}</a>){{end}}</h2>
{{ end }}
{{ if .Descriptor }}
Docker-Content-Digest: <a class="mt" href="{{.Handler}}{{$.Repo}}@{{.Descriptor.Digest}}&mt={{.EscapedMediaType}}&size={{.Descriptor.Size}}">{{.Descriptor.Digest}}<a><br>
Content-Length: {{.Descriptor.Size}}<br>
Content-Type: {{.Descriptor.MediaType}}<br>
{{end}}
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

type RepoParent struct {
	Parent    string
	Child     string
	Separator string
}

type OauthData struct {
	Error    string
	Redirect string
}

type TitleData struct {
	Title string
}
type CosignTag struct {
	Tag   string
	Short string
}

type HeaderData struct {
	Repo             string
	CosignTags       []CosignTag
	JQ               string
	Reference        string
	Up               *RepoParent
	Descriptor       *v1.Descriptor
	Handler          string
	EscapedMediaType string
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
