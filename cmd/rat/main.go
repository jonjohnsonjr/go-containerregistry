package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func NewCmd() *cobra.Command {
	recursive := false
	verbose := false

	cmd := &cobra.Command{
		Use:   "rat",
		Short: "Cat tarballs",
		Args:  cobra.ExactArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			rat(args[0], recursive, verbose)
		},
	}

	cmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "Whether to recurse through tarballs")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Whether to print all header info (formatted as json)")

	return cmd
}

func main() {
	cmd := NewCmd()

	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func rat(filePath string, recursive bool, verbose bool) {
	f, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}

	if !isTar(filePath) {
		log.Fatal("weird name")
	}

	tr, err := tarReader(filePath, f)
	if err != nil {
		log.Fatal(err)
	}

	if err := printFiles(tr, recursive, verbose); err != nil {
		log.Fatal(err)
	}
}

func isTar(name string) bool {
	return strings.HasSuffix(name, ".tar") || strings.HasSuffix(name, ".tar.gz")
}

func tarReader(name string, r io.Reader) (*tar.Reader, error) {
	// Do some magic for gzipped files.
	if strings.HasSuffix(name, ".tar.gz") {
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}

		return tar.NewReader(zr), nil
	}

	return tar.NewReader(r), nil
}

func printFiles(tr *tar.Reader, recursive bool, verbose bool) error {
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			log.Fatal(err)
		}

		if verbose {
			hj, err := json.Marshal(hdr)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s\n", hj)
		} else {
			fmt.Printf("%s\n", hdr.Name)
		}

		if recursive && isTar(hdr.Name) {
			inner, err := tarReader(hdr.Name, tr)
			if err != nil {
				return err
			}
			if err := printFiles(inner, recursive, verbose); err != nil {
				return err
			}
		} else if _, err := io.Copy(ioutil.Discard, tr); err != nil {
			log.Fatal(err)
		}
	}

	return nil
}
