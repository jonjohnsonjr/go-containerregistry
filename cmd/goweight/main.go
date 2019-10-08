package main

import (
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"

	"github.com/dustin/go-humanize"
	"github.com/gorilla/mux"

	gw "github.com/jondot/goweight/pkg"
)

const (
	welcomeMessage = `<html>
<body>
<p>This is a web version of <a href="https://github.com/jondot/goweight">goweight</a></p>
<p>Try it:
<ul>
	<li><a href="/github.com/jondot/goweight">github.com/jondot/goweight</a></li>
</u>
</p>
</body>
</html>`

	templ = `<html>
<head>
<style>
.entry {
        background-color: #eeeeee;
        white-space: nowrap;
	padding: .5em;
	border: 1px solid black;
}
</style>
</head>
<body>
<h1>{{.Package}}</h1>
<h2>Total: {{.Total}}</h2>
{{range .Entries}}
<div class="entry" style="width: {{.Width}}%"><a href="https://godoc.org/{{.Name}}">{{.Name}}</a> {{.SizeHuman}} ({{printf "%.2f" .Percent}}%)</div>
{{end}}
</body>
</html>`
)

type Entry struct {
	Name      string
	SizeHuman string
	Percent   float32
	Width     float32
}

type TemplateInput struct {
	Total   string
	Package string
	Entries []Entry
}

func welcome(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, welcomeMessage)
}

func handler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	arg := vars["arg"]
	if arg == "favicon.ico" {
		log.Printf("skipping favicon.ico")
		return
	}
	command := fmt.Sprintf("goweight %s", arg)
	log.Printf(command)
	if err := handle(w, arg); err != nil {
		fmt.Fprintf(w, "%s: %v", command, err)
	}
}

func handle(w http.ResponseWriter, arg string) error {
	cmd := exec.Command("go", "get", arg)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	weight := gw.NewGoWeight()
	weight.BuildCmd = append(weight.BuildCmd, arg)
	work := weight.BuildCurrent()
	modules := weight.Process(work)

	if len(modules) == 0 {
		return errors.New("no modules")
	}

	max := modules[0].Size
	total := uint64(0)
	for _, module := range modules {
		total += module.Size
	}

	input := TemplateInput{
		Package: arg,
		Total:   humanize.Bytes(total),
		Entries: []Entry{},
	}
	for _, module := range modules {
		input.Entries = append(input.Entries, Entry{
			Name:      module.Name,
			SizeHuman: module.SizeHuman,
			Width:     100.0 * (float32(module.Size) / float32(max)),
			Percent:   100.0 * (float32(module.Size) / float32(total)),
		})
		log.Printf("%8s %s\n", module.SizeHuman, module.Name)
	}
	t, err := template.New("goweight").Parse(templ)
	if err != nil {
		return err
	}
	if err := t.Execute(w, input); err != nil {
		return err
	}
	return nil
}

func main() {
	log.Print("Hello world sample started.")

	// TODO: dispatch based on domain
	r := mux.NewRouter()
	r.HandleFunc("/{arg:.+}", handler)
	r.HandleFunc("/", welcome)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.Handle("/", r)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}
