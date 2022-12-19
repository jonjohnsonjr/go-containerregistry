// Copyright 2022 Google LLC All Rights Reserved.
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
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"

	"github.com/awslabs/soci-snapshotter/compression"
	"github.com/awslabs/soci-snapshotter/ztoc"
	"github.com/google/go-containerregistry/internal/soci"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

func NewCmdSoci(options *[]crane.Option) *cobra.Command {
	cmd := &cobra.Command{
		Hidden: true,
		Use:    "soci",
		Short:  "soci stuff",
		Args:   cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Usage()
		},
	}
	cmd.AddCommand(NewCmdSociIndex(options), NewCmdSociList(options), NewCmdSociServe(options))

	return cmd
}
func NewCmdSociList(options *[]crane.Option) *cobra.Command {
	return &cobra.Command{
		Use:     "list BLOB",
		Short:   "List files in a soci index",
		Example: "crane soci list index.ztoc",
		//Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			toc, err := ztoc.Unmarshal(f)
			if err != nil {
				return err
			}
			for _, fm := range toc.TOC.Metadata {
				fmt.Fprintln(cmd.OutOrStdout(), tarList(fm))
			}
			return nil
		},
	}
}

func NewCmdSociServe(options *[]crane.Option) *cobra.Command {
	index := ""
	cmd := &cobra.Command{
		Use:     "serve BLOB --index FILE",
		Short:   "Read a blob from the registry and generate a soci index",
		Example: "crane soci list index.ztoc",
		//Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			o := crane.GetOptions(*options...)
			ctx := cmd.Context()

			f, err := os.Open(index)
			if err != nil {
				return err
			}
			defer f.Close()

			toc, err := ztoc.Unmarshal(f)
			if err != nil {
				return err
			}

			digest, err := name.NewDigest(args[0], o.Name...)
			if err != nil {
				return err
			}
			opts := o.Remote
			opts = append(opts, remote.WithSize(int64(toc.CompressedArchiveSize)))
			blob, err := remote.Blob(digest, opts...)
			if err != nil {
				return err
			}

			port := os.Getenv("PORT")
			if port == "" {
				port = "8080"
			}

			srv := &http.Server{
				Handler: http.FileServer(http.FS(soci.FS(toc, blob, args[0], 1<<25))),
				Addr:    fmt.Sprintf(":%s", port),
			}

			g, ctx := errgroup.WithContext(ctx)
			g.Go(func() error {
				<-ctx.Done()
				return srv.Shutdown(ctx)
			})
			g.Go(func() error {
				return srv.ListenAndServe()
			})
			return g.Wait()

		},
	}
	cmd.Flags().StringVarP(&index, "index", "i", "", "TODO")
	return cmd
}

func NewCmdSociDigest(options *[]crane.Option) *cobra.Command {
	return &cobra.Command{
		Use:     "digest FILE",
		Short:   "Read a local index file",
		Example: "crane soci digest index.ztoc > digested.ztoc",
		//Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			o := crane.GetOptions(*options...)
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			toc, err := ztoc.Unmarshal(f)
			if err != nil {
				defer f.Close()
				return err
			}
			index, err := compression.NewGzipZinfo(toc.CompressionInfo.Checkpoints)
			if err != nil {
				return err
			}
			digest, err := name.NewDigest(args[0], o.Name...)
			if err != nil {
				return err
			}
			l, err := remote.Layer(digest, o.Remote...)
			if err != nil {
				return err
			}
			digests, err := ztoc.GetPerSpanDigests(l.Compressed, int64(toc.CompressedArchiveSize), index)
			if err != nil {
				defer f.Close()
				return err
			}
			toc.CompressionInfo.SpanDigests = digests

			zr, zdesc, err := ztoc.Marshal(toc)
			if err != nil {
				return err
			}

			if err := json.NewEncoder(cmd.ErrOrStderr()).Encode(zdesc); err != nil {
				return err
			}

			_, err = io.Copy(cmd.OutOrStdout(), zr)
			return err

		},
	}
}

// NewCmdSociIndex creates a new cobra.Command for the soci subcommand.
func NewCmdSociIndex(options *[]crane.Option) *cobra.Command {
	return &cobra.Command{
		Use:     "index BLOB",
		Short:   "Read a blob from the registry and generate a soci index",
		Example: "crane soci index ubuntu@sha256:4c1d20cdee96111c8acf1858b62655a37ce81ae48648993542b7ac363ac5c0e5 > index.ztoc",
		//Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			o := crane.GetOptions(*options...)

			digest, err := name.NewDigest(args[0], o.Name...)
			if err != nil {
				return err
			}
			l, err := remote.Layer(digest, o.Remote...)
			if err != nil {
				return err
			}

			size, err := l.Size()
			if err != nil {
				return err
			}
			toc, err := ztoc.BuildZtocFromReader(l.Compressed, int64(1<<22), "crane", size)
			if err != nil {
				return err
			}

			zr, zdesc, err := ztoc.Marshal(toc)
			if err != nil {
				return err
			}

			if err := json.NewEncoder(cmd.ErrOrStderr()).Encode(zdesc); err != nil {
				return err
			}

			_, err = io.Copy(cmd.OutOrStdout(), zr)
			return err

			//return json.NewEncoder(cmd.OutOrStdout()).Encode(toc)

		},
	}
}

// E.g. from ubuntu
// drwxr-xr-x 0/0               0 2022-11-29 18:07 var/lib/systemd/deb-systemd-helper-enabled/
// lrwxrwxrwx 0/0               0 2022-11-29 18:04 var/run -> /run
// hrwxr-xr-x 0/0               0 2022-09-05 06:33 usr/bin/uncompress link to usr/bin/gunzip
// drwxrwxrwt 0/0               0 2022-11-29 18:04 run/lock/
// -rwsr-xr-x 0/0           72072 2022-11-24 04:05 usr/bin/gpasswd
func tarList(fm ztoc.FileMetadata) string {
	ts := fm.ModTime.Format("2006-01-02 15:04")
	ug := fmt.Sprintf("%d/%d", fm.UID, fm.GID)
	mode := modeStr(fm)
	padding := 18 - len(ug)
	s := fmt.Sprintf("%s %s %*d %s %s", mode, ug, padding, fm.UncompressedSize, ts, fm.Name)
	if fm.Linkname != "" {
		if soci.TarType(fm.Type) == tar.TypeLink {
			s += " link to " + fm.Linkname
		} else {
			s += " -> " + fm.Linkname
		}
	}
	return s
}

func modeStr(fm ztoc.FileMetadata) string {
	hdr := soci.TarHeader(&fm)
	fi := hdr.FileInfo()
	mm := fi.Mode()

	mode := []byte(fs.FileMode(fm.Mode).String())
	mode[0] = typeStr(soci.TarType(fm.Type))

	if mm&fs.ModeSetuid != 0 {
		if mm&0100 != 0 {
			mode[3] = 's'
		} else {
			mode[3] = 'S'
		}
	}
	if mm&fs.ModeSetgid != 0 {
		if mm&0010 != 0 {
			mode[6] = 's'
		} else {
			mode[6] = 'S'
		}
	}
	if mm&fs.ModeSticky != 0 {
		if mm&0001 != 0 {
			mode[9] = 't'
		} else {
			mode[9] = 'T'
		}
	}
	return string(mode)
}
func typeStr(t byte) byte {
	switch t {
	case tar.TypeReg:
		return '-'
	case tar.TypeLink:
		return 'h'
	case tar.TypeSymlink:
		return 'l'
	case tar.TypeDir:
		return 'd'
	case tar.TypeChar:
		return 'c'
	case tar.TypeBlock:
		return 'b'
	case tar.TypeFifo:
		return 'p'
	}

	return '?'
}
