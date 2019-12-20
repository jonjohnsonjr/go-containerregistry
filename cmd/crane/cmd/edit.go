// Copyright 2018 Google LLC All Rights Reserved.
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
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/cmd/crane/internal/editor"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/spf13/cobra"
)

func init() { Root.AddCommand(NewCmdEdit()) }

// NewCmdEdit creates a new cobra.Command for the edit subcommand.
func NewCmdEdit() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit",
		Short: "Edit the contents of an image.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Usage()
		},
	}
	cmd.AddCommand(NewCmdEditManifest(), NewCmdEditConfig(), NewCmdEditFs())

	return cmd
}

// NewCmdConfig creates a new cobra.Command for the config subcommand.
func NewCmdEditConfig() *cobra.Command {
	return &cobra.Command{
		Use:   "config",
		Short: "Edit an image's config file.",
		Example: `  # Edit ubuntu's config file
  crane edit config ubuntu

  # Overwrite ubuntu's config file with '{}'
  echo '{}' | crane edit config ubuntu`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ref, err := editConfig(args[0])
			if err != nil {
				log.Fatalf("editing config: %v", err)
			}
			fmt.Println(ref.String())
		},
	}
}

// NewCmdManifest creates a new cobra.Command for the manifest subcommand.
func NewCmdEditManifest() *cobra.Command {
	oci := false
	cmd := &cobra.Command{
		Use:   "manifest",
		Short: "Edit an image's manifest.",
		Example: `  # Edit ubuntu's config file
  crane edit config ubuntu

  # Overwrite ubuntu's config file with '{}'
  echo '{}' | crane edit config ubuntu

  # Edit the manifest and write back using an OCI Content-Type. This is useful
  # for e.g. adding an "annotations" field to a manifest.
  crane edit manifest ubuntu --oci`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ref, err := editManifest(args[0], oci)
			if err != nil {
				log.Fatalf("editing config: %v", err)
			}
			fmt.Println(ref.String())
		},
	}
	cmd.Flags().BoolVar(&oci, "oci", false, "Use OCI Content-Type headers")

	return cmd
}

// NewCmdExport creates a new cobra.Command for the export subcommand.
func NewCmdEditFs() *cobra.Command {
	name := ""
	cmd := &cobra.Command{
		Use:   "fs IMAGE",
		Short: "Edit the contents of an image's filesystem.",
		Example: `  # Edit motd-news using $EDITOR
  crane edit fs ubuntu -f /etc/default/motd-news

  # Overwrite motd-news with 'ENABLED=0'
  echo 'ENABLED=0' | crane edit fs ubuntu -f /etc/default/motd-news`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ref, err := editFile(args[0], name)
			if err != nil {
				log.Fatalf("editing file: %v", err)
			}
			fmt.Println(ref.String())
		},
	}
	cmd.Flags().StringVarP(&name, "filename", "f", "", "Edit the given filename")
	cmd.MarkFlagRequired("filename")

	return cmd
}

func stdin() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		log.Printf("stdin: %v", err)
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) == 0
}

func edit(ext string, in io.Reader) ([]byte, error) {
	edit := editor.NewDefaultEditor([]string{"EDITOR"})
	edited, _, err := edit.LaunchTempFile(fmt.Sprintf("%s-edit-", filepath.Base(os.Args[0])), ext, in)
	return edited, err
}

func editConfig(src string) (name.Reference, error) {
	img, err := crane.Pull(src)
	if err != nil {
		return nil, err
	}

	og, err := img.Digest()
	if err != nil {
		return nil, err
	}
	log.Printf("original image: %s@%s", src, og)

	var edited []byte
	if stdin() {
		b, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		edited = b
	} else {
		rcf, err := img.RawConfigFile()
		if err != nil {
			return nil, err
		}
		edited, err = edit(".json", bytes.NewReader(rcf))
		if err != nil {
			return nil, err
		}
	}

	cf, err := v1.ParseConfigFile(bytes.NewReader(edited))
	if err != nil {
		return nil, err
	}

	img, err = mutate.ConfigFile(img, cf)
	if err != nil {
		return nil, err
	}

	digest, err := img.Digest()
	if err != nil {
		return nil, err
	}

	dst := src
	ref, err := name.ParseReference(src)
	if err != nil {
		return nil, err
	}
	if _, ok := ref.(name.Digest); ok {
		dst = fmt.Sprintf("%s@%s", ref.Context(), digest)
	}

	dstRef, err := name.ParseReference(dst)
	if err != nil {
		return nil, err
	}

	if err := remote.Write(dstRef, img, remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		return nil, err
	}

	return dstRef, nil
}

func editManifest(src string, oci bool) (name.Reference, error) {
	ref, err := name.ParseReference(src)
	if err != nil {
		return nil, err
	}

	desc, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, err
	}
	log.Printf("original image: %s@%s", src, desc.Digest)

	var edited []byte
	if stdin() {
		b, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		edited = b
	} else {
		edited, err = edit(".json", bytes.NewReader(desc.Manifest))
		if err != nil {
			return nil, err
		}
	}

	digest, _, err := v1.SHA256(bytes.NewReader(edited))
	if err != nil {
		return nil, err
	}

	dst := src
	if _, ok := ref.(name.Digest); ok {
		dst = fmt.Sprintf("%s@%s", ref.Context(), digest)
	}
	dstRef, err := name.ParseReference(dst)
	if err != nil {
		return nil, err
	}

	// We don't expose a way to easily just PUT a manifest, so there's some boilerplate.
	reg := dstRef.Context().Registry
	auth, err := authn.DefaultKeychain.Resolve(reg)
	if err != nil {
		return nil, err
	}
	scopes := []string{dstRef.Scope(transport.PushScope)}
	tr, err := transport.New(reg, auth, http.DefaultTransport, scopes)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: tr}

	u := url.URL{
		Scheme: dstRef.Context().Registry.Scheme(),
		Host:   dstRef.Context().RegistryStr(),
		Path:   fmt.Sprintf("/v2/%s/manifests/%s", dstRef.Context().RepositoryStr(), dstRef.Identifier()),
	}

	req, err := http.NewRequest(http.MethodPut, u.String(), bytes.NewBuffer(edited))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", string(convert(desc.MediaType, oci)))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := transport.CheckError(resp, http.StatusOK, http.StatusCreated, http.StatusAccepted); err != nil {
		return nil, err
	}

	return dstRef, nil
}

func editFile(src, file string) (name.Reference, error) {
	img, err := crane.Pull(src)
	if err != nil {
		return nil, err
	}

	og, err := img.Digest()
	if err != nil {
		return nil, err
	}
	log.Printf("original image: %s@%s", src, og)

	// If stdin has content, read it in and use that for the file.
	// Otherwise, scran through the image and open that file in an  editor.
	var (
		edited []byte
		header *tar.Header
	)
	if stdin() {
		b, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		edited = b
		header = blankHeader(file)
	} else {
		f, h, err := findFile(img, file)
		if err != nil {
			return nil, err
		}
		edited, err = edit(filepath.Ext(h.Name), f)
		if err != nil {
			return nil, err
		}
		header = h
	}

	// TODO: pre-allocate
	buf := bytes.NewBuffer(nil)
	tw := tar.NewWriter(buf)

	header.Size = int64(len(edited))
	if err := tw.WriteHeader(header); err != nil {
		return nil, err
	}
	if _, err := io.Copy(tw, bytes.NewReader(edited)); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}

	fileBytes := buf.Bytes()
	fileLayer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return ioutil.NopCloser(bytes.NewBuffer(fileBytes)), nil
	})
	if err != nil {
		return nil, err
	}
	img, err = mutate.Append(img, mutate.Addendum{
		Layer: fileLayer,
		History: v1.History{
			Author:    "crane",
			CreatedBy: strings.Join(os.Args, " "),
		},
	})
	if err != nil {
		return nil, err
	}

	digest, err := img.Digest()
	if err != nil {
		return nil, err
	}

	dst := src
	ref, err := name.ParseReference(src)
	if err != nil {
		return nil, err
	}
	if _, ok := ref.(name.Digest); ok {
		dst = fmt.Sprintf("%s@%s", ref.Context(), digest)
	}

	dstRef, err := name.ParseReference(dst)
	if err != nil {
		return nil, err
	}

	if err := remote.Write(dstRef, img, remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		return nil, err
	}

	return dstRef, nil
}

func findFile(img v1.Image, name string) (io.Reader, *tar.Header, error) {
	name = normalize(name)
	tr := tar.NewReader(mutate.Extract(img))
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("reading tar: %v", err)
		}
		if normalize(header.Name) == name {
			return tr, header, nil
		}
	}

	// If we don't find the file, we should create a new one.
	return bytes.NewBufferString(""), blankHeader(name), nil
}

func blankHeader(name string) *tar.Header {
	return &tar.Header{
		Name:     name,
		Typeflag: tar.TypeReg,
		// Use a fixed Mode, so that this isn't sensitive to the directory and umask
		// under which it was created. Additionally, windows can only set 0222,
		// 0444, or 0666, none of which are executable.
		Mode: 0555,
	}
}

func normalize(name string) string {
	return filepath.Clean("/" + name)
}

func convert(mt types.MediaType, oci bool) types.MediaType {
	if !oci {
		return mt
	}

	if mt == types.DockerManifestList {
		return types.OCIImageIndex
	}
	return types.OCIManifestSchema1
}
