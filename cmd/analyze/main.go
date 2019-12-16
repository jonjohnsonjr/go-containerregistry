package main

import (
	"bytes"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/GoogleContainerTools/container-diff/differs"
	"github.com/GoogleContainerTools/container-diff/pkg/util"
	"github.com/gorilla/mux"
)

var welcomeMessage string

func init() {
	analyzers := make([]string, 0, len(differs.Analyzers))
	for k := range differs.Analyzers {
		analyzers = append(analyzers, k)
	}
	type Data struct {
		Analyzers []string
	}
	var buf bytes.Buffer
	tmpl, err := template.New("manifestTemplate").Parse(welcomeTemplate)
	if err != nil {
		panic(err)
	}
	tmpl.Execute(&buf, Data{analyzers})
	welcomeMessage = buf.String()
}

const welcomeTemplate = `<html>
<body>
<p>This is a web version of <a href="https://github.com/GoogleContainerTools/container-diff">container-diff analyze</a>.</p>
<p>Try it:
<ul>
{{ range .Analyzers }}
	<li><a href="/debian?type={{.}}">debian?type={{.}}</a></li>
{{ end }}
</u>
</p>
</body>
</html>`

func welcome(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, welcomeMessage)
}

func handler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	arg := vars["arg"]
	command := fmt.Sprintf("container-diff analyze %s", arg)
	log.Printf(command)
	if err := analyze(w, r, arg); err != nil {
		fmt.Fprintf(w, "%s: %v", command, err)
	}
}

func analyze(w http.ResponseWriter, r *http.Request, arg string) error {
	tmpdir, err := ioutil.TempDir("", "")
	if err != nil {
		return err
	}

	types := r.URL.Query()["type"]
	if len(types) == 0 {
		types = []string{"size"}
	}
	analyzers, err := differs.GetAnalyzers(types)
	if err != nil {
		return err
	}
	if len(analyzers) == 0 {
		return fmt.Errorf("no analyzers for %v", types)
	}
	img, err := util.GetImage(arg, true, tmpdir)
	if err != nil {
		return err
	}

	req := differs.SingleRequest{
		Image:        img,
		AnalyzeTypes: analyzers,
	}

	analysis, err := req.GetAnalysis()
	if err != nil {
		return err
	}
	for k, result := range analysis {
		if err := result.OutputText(w, k, ""); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	log.Print("Hello world sample started.")

	r := mux.NewRouter()
	r.HandleFunc("/", welcome)
	r.HandleFunc("/{arg:.*}", handler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.Handle("/", r)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}
