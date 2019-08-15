package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"io/ioutil"
	"log"
	"os"
	"time"
)

func main() {
	var (
		b   []byte
		err error
	)
	if len(os.Args) < 2 {
		os.Args = append(os.Args, "-")
	}
	if os.Args[1] == "-" {
		b, err = ioutil.ReadAll(os.Stdin)
	} else {
		b, err = ioutil.ReadFile(os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}

	buf := bytes.NewBuffer(b)
	for level := gzip.NoCompression; level <= gzip.BestCompression; level++ {
		output := bufio.NewWriterSize(os.Stdout, len(b))
		now := time.Now()
		gw, err := gzip.NewWriterLevel(output, level)
		if err != nil {
			log.Fatal(err)
		}
		defer gw.Close()
		_, err = io.Copy(gw, bytes.NewBuffer(buf.Bytes()))
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("level %d \t %v \t %d bytes\n", level, time.Since(now), output.Buffered())
	}
}

func foo(level int) {
	gw, err := gzip.NewWriterLevel(os.Stdout, level)
	if err != nil {
		log.Fatal(err)
	}
	defer gw.Close()
	_, err = io.Copy(gw, os.Stdin)
	if err != nil {
		log.Fatal(err)
	}
}
