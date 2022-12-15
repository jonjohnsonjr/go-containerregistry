// Copyright 2020 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"bufio"
	"io"
	"log"
	"os"
	"path/filepath"
	"syscall"

	"github.com/awslabs/soci-snapshotter/ztoc"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

// NewCmdBlob creates a new cobra.Command for the blob subcommand.
func NewCmdBlob(options *[]crane.Option) *cobra.Command {
	return &cobra.Command{
		Use:     "blob BLOB",
		Short:   "Read a blob from the registry",
		Example: "crane blob ubuntu@sha256:4c1d20cdee96111c8acf1858b62655a37ce81ae48648993542b7ac363ac5c0e5 > blob.tar.gz",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			src := args[0]

			o := crane.GetOptions(*options...)

			digest, err := name.NewDigest(src, o.Name...)
			if err != nil {
				return err
			}

			l, err := remote.Layer(digest, o.Remote...)
			if err != nil {
				return err
			}
			log.Printf("Layer")

			fname := filepath.Join(os.TempDir(), digest.Identifier())
			if err := syscall.Mkfifo(fname, 0666); err != nil {
				return err
			}
			log.Printf("Mkfifo")
			defer os.Remove(fname)

			f, err := os.OpenFile(fname, os.O_WRONLY, os.ModeNamedPipe)
			if err != nil {
				return err
			}
			log.Printf("OpenFile")

			/*
				b, err := remote.Blob(digest, o.Remote...)
				if err != nil {
					return err
				}
				_ = b
			*/

			var g errgroup.Group
			g.Go(func() error {
				log.Printf("go() 1")
				defer f.Close()
				bw := bufio.NewWriterSize(f, 2<<16)
				log.Printf("Compressed()")
				rc, err := l.Compressed()
				if err != nil {
					return err
				}
				defer rc.Close()
				s := snooper{bw}
				log.Printf("Copy()")
				if _, err := io.Copy(&s, rc); err != nil {
					return err
				}
				log.Printf("Flush()")
				if err := bw.Flush(); err != nil {
					return err
				}
				log.Printf("returning")
				return nil
			})

			g.Go(func() error {
				log.Printf("go() 2")
				// return nil

				log.Printf("build")
				toc, err := ztoc.BuildZtoc(fname, int64(1<<22), "crane")
				if err != nil {
					return err
				}
				log.Printf("ztoc: %v", toc)
				return nil
			})

			return g.Wait()
		},
	}
}

type snooper struct {
	w io.Writer
}

func (s *snooper) Write(p []byte) (n int, err error) {
	log.Printf("about to write len(p) == %d bytes", len(p))
	n, err = s.w.Write(p)
	log.Printf("wrote %d, %v", n, err)
	return
}
