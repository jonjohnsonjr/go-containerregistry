package main

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"

	"github.com/gorilla/mux"
)

const (
	welcomeMessage = `<html>
<body>
<p>This is a web version of <a href="https://github.com/kisielk/godepgraph">godepgraph</a></p>
<p>Try it:
<ul>
	<li><a href="/github.com/kisielk/godepgraph">github.com/kisielk/godepgraph</a></li>
</u>
</p>
</body>
</html>`

	// https://github.com/magjac/d3-graphviz
	templ = `<html>
<head>
</head>
<body>
<h1>{{.Package}}</h1>
<script src="//d3js.org/d3.v4.min.js"></script>
<script src="http://viz-js.com/bower_components/viz.js/viz-lite.js"></script>
<script src="https://github.com/magjac/d3-graphviz/releases/download/v0.0.4/d3-graphviz.min.js"></script>
<div id="graph" style="text-align: center;"></div>
<script>
d3.select("#graph").graphviz().renderDot('{{.Dot}}');
</script>
</div>
</body>
</html>`
)

func init() {
	tmp, err := template.New("goweight").Parse(templ)
	if err != nil {
		log.Fatal(err)
	}
	t = tmp
	cache = make(map[string]*TemplateInput)
}

var (
	work  sync.Map
	cache map[string]*TemplateInput
	t     *template.Template
)

type Entry struct {
	Name      string
	SizeHuman string
	Percent   float32
	Width     float32
}

type TemplateInput struct {
	Package string
	Dot     string
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
	if err := handle(w, r, arg, r.URL.String()); err != nil {
		fmt.Fprintf(w, "%s: %v", arg, err)
	}
}

func kodata(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	arg := vars["arg"]
	root := os.Getenv("KO_DATA_PATH")
	http.ServeFile(w, r, path.Join(root, arg))
}

func handle(w http.ResponseWriter, r *http.Request, arg, key string) error {
	// TODO: I'm pretty sure what I actually want is a channel.
	v, ok := work.LoadOrStore(key, &sync.Once{})
	if ok {
		log.Printf("cached %s", arg)
	}
	once, ok := v.(*sync.Once)
	if !ok {
		log.Fatalf("something went very wrong: %s", arg)
	}
	var err error
	once.Do(func() {
		err = func() error {
			log.Printf("go get %s", arg)
			cmd := exec.Command("go", "get", arg)
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return err
			}

			args := []string{}
			for k, v := range r.URL.Query() {
				args = append(args, fmt.Sprintf("-%s=%s", k, strings.Join(v, ",")))
			}
			args = append(args, arg)

			gdg := exec.Command("godepgraph", args...)

			var buf bytes.Buffer
			gdg.Stderr = os.Stderr
			gdg.Stdout = &buf
			log.Printf("godepgraph %s", arg)
			if err := gdg.Run(); err != nil {
				return fmt.Errorf("godepgraph %s: %v\nConsider using ?stoponerror=false", strings.Join(args, " "), err)
			}

			cache[key] = &TemplateInput{
				Package: arg,
				Dot:     buf.String(),
			}
			return nil
		}()
	})
	if err != nil {
		return err
	}
	input, ok := cache[key]
	if !ok {
		log.Fatalf("something went very wrong: %s", arg)
	}
	log.Printf("rendering %s", arg)
	if err := t.Execute(w, input); err != nil {
		return err
	}

	return nil
}

func main() {
	log.Print("Hello world sample started.")

	// TODO: dispatch based on domain
	r := mux.NewRouter()
	r.HandleFunc("/kodata/{arg:.+}", kodata)
	r.HandleFunc("/{arg:.+}", handler)
	r.HandleFunc("/", welcome)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.Handle("/", r)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}
