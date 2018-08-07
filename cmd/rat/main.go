package main

import (
	"archive/tar"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	filePath := os.Args[1]

	f, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", hdr.Name)
		if _, err := io.Copy(ioutil.Discard, tr); err != nil {
			log.Fatal(err)
		}
	}
}
