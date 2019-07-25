package main

import (
	"archive/tar"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/v1/filesystem"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	_ "github.com/motemen/go-loghttp/global"
)

func main() {
	log.Print("imgfs started")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	if len(os.Args) < 2 {
		log.Fatalf("usage: %s <image>", os.Args[0])
	}

	fs, err := makefs(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	log.Print("opening nothing")
	fs.Open("abcdefg")

	log.Print("listening")
	http.Handle("/", http.FileServer(fs))
	// http.Handle("/", http.FileServer(http.Dir("/tmp")))
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))

	// f, err := fs.Open("etc/terminfo/README")
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// stat, err := f.Stat()
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// log.Println(stat.Name())

	// b, err := ioutil.ReadAll(f)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// fmt.Println(string(b))
}

func makefs(image string) (filesystem.FileSystem, error) {
	img, err := crane.Pull(image)
	if err != nil {
		return nil, err
	}

	return filesystem.FromTarball(tar.NewReader(mutate.Extract(img))), nil
}
