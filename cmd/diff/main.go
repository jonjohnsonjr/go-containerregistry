package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/GoogleContainerTools/container-diff/differs"
	"github.com/GoogleContainerTools/container-diff/pkg/util"
	"github.com/gorilla/mux"
)

const welcomeMessage = `<html>
<body>
<p>This is a web version of <a href="https://github.com/GoogleContainerTools/container-diff">container-diff</a></p>
<p>It supports analyze and diff.</p>
<p>Try it:
<ul>
	<li><a href="/analyze/ubuntu">analyze/ubuntu</a></li>
	<li><a href="/diff/ubuntu+debian">diff/ubuntu+debian</a></li>
</u>
</p>
</body>
</html>`

func welcome(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, welcomeMessage)
}

var (
	tmpdir, _ = ioutil.TempDir("", "")
)

func diffHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	cmd := vars["command"]
	arg := vars["arg"]
	command := fmt.Sprintf("container-diff %s %s", cmd, arg)
	log.Printf(command)
	if err := doDiff(w, r, cmd, arg); err != nil {
		fmt.Fprintf(w, "%s: %v", command, err)
	}
}

func doDiff(w http.ResponseWriter, r *http.Request, cmd, arg string) error {
	types := r.URL.Query()["type"]
	if len(types) == 0 {
		types = []string{"size"}
	}
	switch cmd {
	case "analyze":
		fmt.Fprintf(w, "container-diff analyze %s", arg)
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
	case "diff":
		args := strings.Split(arg, "+")
		if len(args) != 2 {
			return fmt.Errorf("expected 2 args, got %v", args)
		}
		fmt.Fprintf(w, "container-diff diff %s %s", args[0], args[1])
	default:
		fmt.Fprintf(w, welcomeMessage)
	}
	return nil
}

func main() {
	log.Print("Hello world sample started.")

	r := mux.NewRouter()
	r.HandleFunc("/{command}/{arg:.*}", diffHandler)
	r.HandleFunc("/", welcome)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.Handle("/", r)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}
