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
	"os"

	"github.com/awslabs/soci-snapshotter/compression"
	"github.com/awslabs/soci-snapshotter/ztoc"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/cobra"
)

// NewCmdSoci creates a new cobra.Command for the soci subcommand.
func NewCmdSoci(options *[]crane.Option) *cobra.Command {
	var index string
	var list bool
	cmd := &cobra.Command{
		Use:     "soci BLOB",
		Short:   "Read a blob from the registry and generate a soci index",
		Example: "crane soci ubuntu@sha256:4c1d20cdee96111c8acf1858b62655a37ce81ae48648993542b7ac363ac5c0e5 > index.ztoc",
		//Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			o := crane.GetOptions(*options...)

			// TODO: subcommands

			var toc *ztoc.Ztoc
			if index == "" {
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
				toc, err = ztoc.BuildZtocFromReader(l.Compressed, int64(1<<22), "crane", size)
				if err != nil {
					return err
				}
			} else {
				f, err := os.Open(index)
				if err != nil {
					return err
				}
				toc, err = ztoc.Unmarshal(f)
				if err != nil {
					defer f.Close()
					return err
				}
				index, err := compression.NewGzipZinfo(toc.CompressionInfo.Checkpoints)
				if err != nil {
					defer f.Close()
					return err
				}
				if !list {
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
					digests, err := ztoc.GetPerSpanDigests(l.Compressed, size, index)
					if err != nil {
						defer f.Close()
						return err
					}
					toc.CompressionInfo.SpanDigests = digests
				}
			}

			if list {
				for _, fm := range toc.TOC.Metadata {
					fmt.Fprintln(cmd.OutOrStdout(), tarList(fm))
				}
				return nil
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
	cmd.Flags().StringVarP(&index, "index", "i", "", "Already generated index, will modify ztoc.json to add span digests")
	cmd.Flags().BoolVarP(&list, "list", "t", false, "List files in index")
	return cmd
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
		if getType(fm.Type) == tar.TypeLink {
			s += " link to " + fm.Linkname
		} else {
			s += " -> " + fm.Linkname
		}
	}
	return s
}

func tarHeader(fm ztoc.FileMetadata) *tar.Header {
	return &tar.Header{
		Typeflag: getType(fm.Type),
		Name:     fm.Name,
		Linkname: fm.Linkname,

		Size:  int64(fm.UncompressedSize),
		Mode:  fm.Mode,
		Uid:   fm.UID,
		Gid:   fm.GID,
		Uname: fm.Uname,
		Gname: fm.Gname,

		ModTime: fm.ModTime,

		Devmajor: fm.Devmajor,
		Devminor: fm.Devminor,

		Xattrs: fm.Xattrs,
	}
}

func modeStr(fm ztoc.FileMetadata) string {
	hdr := tarHeader(fm)
	fi := hdr.FileInfo()
	mm := fi.Mode()

	mode := []byte(fs.FileMode(fm.Mode).String())
	mode[0] = typeStr(getType(fm.Type))

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

// returns tar.Typeflag
func getType(t string) byte {
	switch t {
	case "hardlink":
		return tar.TypeLink
	case "symlink":
		return tar.TypeSymlink
	case "dir":
		return tar.TypeDir
	case "reg":
		return tar.TypeReg
	case "char":
		return tar.TypeChar
	case "block":
		return tar.TypeBlock
	case "fifo":
		return tar.TypeFifo
	default:
		return tar.TypeReg
	}
}
