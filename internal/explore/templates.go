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
	"fmt"
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
	gcrane     = `<a class="mt" href="https://github.com/google/go-containerregistry/blob/main/cmd/gcrane/README.md">gcrane</a>`
	craneLink  = `<a class="mt" href="https://github.com/google/go-containerregistry/blob/main/cmd/crane/README.md">crane</a>`
	subLinkFmt = `<a class="mt" href="https://github.com/google/go-containerregistry/blob/main/cmd/crane/doc/crane_%s.md">%s</a>`
)

func crane(sub string) string {
	if sub == "" {
		return craneLink
	}

	subLink := fmt.Sprintf(subLinkFmt, sub, sub)
	return craneLink + " " + subLink
}

const (
	landingPage = `
<html>
<body>
<head>
<title>Registry Explorer</title>
<link rel="icon" href="/favicon.svg">
<style>
.mt:hover {
	text-decoration: underline;
}

.mt {
	color: inherit;
	text-decoration: inherit;
}

.link {
	position: relative;
	bottom: .125em;
}

.crane {
	height: 1em;
	width: 1em;
}

.top {
	color: inherit;
	text-decoration: inherit;
}

body {
	font-family: monospace;
	width: fit-content;
	overflow-wrap: anywhere;
	padding: 12px;
}
</style>
</head>
<h1><a class="top" href="/"><img class="crane" src="/favicon.svg"/> <span class="link">Registry Explorer</span></a></h1>
<p>
This beautiful tool allows you to <em>explore</em> the contents of a registry interactively.
</p>
<p>
You can even drill down into layers to explore an image's filesystem.
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
<p>
<h4>Interesting examples</h4>
<ul>
  <li><a href="/?image=gcr.io/distroless/static">gcr.io/distroless/static:latest</a></li>
  <li><a href="/?repo=ghcr.io/homebrew/core/crane">ghcr.io/homebrew/core/crane</a></li>
  <li><a href="/?repo=registry.k8s.io">registry.k8s.io</a></li>
  <li><a href="/?image=registry.k8s.io/bom/bom:sha256-499bdf4cc0498bbfb2395f8bbaf3b7e9e407cca605aecc46b2ef1b390a0bc4c4.sig">registry.k8s.io/bom/bom:sha256-499bdf4cc0498bbfb2395f8bbaf3b7e9e407cca605aecc46b2ef1b390a0bc4c4.sig</a></li>
  <li><a href="/?image=cgr.dev/chainguard/ko:sha256-435f610505cd96eba44dcb13987509ee1ad80030ad970bb4583880259dc21b7e.sbom">cgr.dev/chainguard/ko:sha256-435f610505cd96eba44dcb13987509ee1ad80030ad970bb4583880259dc21b7e.sbom</a></li>
  <li><a href="/?image=docker/dockerfile:1.5.1">docker/dockerfile:1.5.1</a></li>
  <li><a href="/?image=pengfeizhou/test-oci:sha256-04eaff953b0066d7e4ea2e822eb5c31be0742fca494561336f0912fabc246760">pengfeizhou/test-oci:sha256-04eaff953b0066d7e4ea2e822eb5c31be0742fca494561336f0912fabc246760</a></li>
  <li><a href="/?image=tianon/true:oci">tianon/true:oci</a></li>
  <li><a href="/?image=ghcr.io/stargz-containers/node:13.13.0-esgz">ghcr.io/stargz-containers/node:13.13.0-esgz</a></li>

</ul>
</p>
<h3>FAQ</h3>
<h4>How does this work?</h4>
<p>
This service lives on <a href="https://cloud.run">Cloud Run</a> and uses <a href="https://github.com/google/go-containerregistry">google/go-containerregistry</a> for registry interactions.
</p>
<h4>Isn't this expensive for the registry?</h4>
<p>
Not really! The first time a layer is accessed, I download and index it. Browsing the filesystem just uses that index, and opening a file uses Range requests to load small chunks of the layer as needed.
</p>
<h4>That can't be true, gzip doesn't support random access!</h4>
<p>
That's not a question.
</p>
<h4>Okay then, how does random access work if the layers are gzipped tarballs?</h4>
<p>Great question! See <a href="https://github.com/madler/zlib/blob/master/examples/zran.c">here</a>.</p>
<p>Tl;dr, you can seek to an arbitrary position in a gzip stream if you know the 32KiB of uncompressed data that comes just before it, so by storing ~1% of the uncompressed layer size, I can jump ahead to predetermined locations and start reading from there rather than reading the entire layer.</p>
<p>Thanks <a href="https://github.com/aidansteele">@aidansteele</a>!</p>
</p>
</body>
</html>
`

	oauthTemplate = `
<html>
<body>
<head>
<title>Registry Explorer</title>
<link rel="icon" href="/favicon.svg">
<style>
.mt:hover {
	text-decoration: underline;
}

.mt {
	color: inherit;
	text-decoration: inherit;
}

.link {
	position: relative;
	bottom: .125em;
}

.crane {
	height: 1em;
	width: 1em;
}

.top {
	color: inherit;
	text-decoration: inherit;
}

body {
	font-family: monospace;
	width: fit-content;
	overflow-wrap: anywhere;
	padding: 12px;
}
</style>
</head>
<h1><a class="top" href="/"><img class="crane" src="/favicon.svg"/> <span class="link">Registry Explorer</span></a></h1>
<p>
It looks like we encountered an auth error:
</p>
<code>
{{.Error}}
</code>
<p>
If you trust <a class="mt" href="https://github.com/jonjohnsonjr">me</a>, click <a href="{{.Redirect}}">here</a> for oauth to use your own credentials.
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

.link {
	position: relative;
	bottom: .125em;
}

.crane {
	height: 1em;
	width: 1em;
}

.top {
	color: inherit;
	text-decoration: inherit;
}

body {
	font-family: monospace;
	width: fit-content;
	overflow-wrap: anywhere;
	padding: 12px;
}

pre {
	white-space: pre-wrap;
}

.indent {
	margin-left: 2em;
}

.noselect {
	user-select: none;
	-webkit-user-select: none;
	width: fit-content;
	overflow-wrap: none;
	padding-right: 1em;
	text-align: right;
	white-space: nowrap;
}

td {
	vertical-align: top;
}
</style>
</head>
`

	bodyTemplate = `
<body>
<div>
<h1><a class="top" href="/"><img class="crane" src="/favicon.svg"/> <span class="link">Registry Explorer</span></a></h1>
{{ if .Up }}
<h2>{{ if and (ne .Up.Parent "docker.io") (ne .Up.Parent "index.docker.io") }}<a class="mt" href="/?repo={{.Up.Parent}}">{{.Up.Parent}}</a>{{else}}{{.Up.Parent}}{{end}}{{.Up.Separator}}{{if .Handler }}<a class="mt" href="/{{.Handler}}{{.Reference}}{{if .EscapedMediaType}}&mt={{.EscapedMediaType}}{{end}}">{{.Up.Child}}</a>{{else}}{{.Up.Child}}{{end}}{{ range .CosignTags }} (<a href="/?image={{$.Repo}}:{{.Tag}}">{{.Short}}</a>){{end}}</h2>
{{ else }}
<h2>{{.Reference}}{{ range .CosignTags }} (<a href="/?image={{$.Repo}}:{{.Tag}}">{{.Short}}</a>){{end}}</h2>
{{ end }}
{{ if .Descriptor }}
Docker-Content-Digest: <a class="mt" href="/{{.Handler}}{{$.Repo}}@{{.Descriptor.Digest}}{{if .EscapedMediaType}}&mt={{.EscapedMediaType}}{{end}}&size={{.Descriptor.Size}}">{{.Descriptor.Digest}}<a><br>
Content-Length: {{if .SizeLink}}<a class="mt" href="{{.SizeLink}}">{{.Descriptor.Size}}</a>{{else}}{{.Descriptor.Size}}{{end}}<br>
Content-Type: {{if .MediaTypeLink}}<a class="mt" href="/{{.MediaTypeLink}}">{{.Descriptor.MediaType}}</a>{{else}}{{.Descriptor.MediaType}}{{end}}<br>
{{end}}
</div>
{{ if .JQ }}
<h4><span class="noselect">$</span>{{.JQ}}</h4>

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
	MediaTypeLink    string
	SizeLink         string
}
