// Copyright 2021 Google LLC All Rights Reserved.
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

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// TODO: Adopt standard flags for this stuff, maybe use cobra.
// TODO: Different kinds of signatures.
var keyPath = flag.String("key", "", "private key")
var verbose = flag.Bool("v", false, "log lots of stuff")

func main() {
	flag.Parse()

	logs.Progress.SetOutput(os.Stderr)
	logs.Warn.SetOutput(os.Stderr)
	if *verbose {
		logs.Debug.SetOutput(os.Stderr)
	}

	ref, err := name.ParseReference(flag.Args()[0])
	if err != nil {
		log.Fatal(err)
	}

	output, err := pushIndex(ref)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(output)
}

func sign(payload []byte) ([]byte, error) {
	b, err := ioutil.ReadFile(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, errors.New("pem.Decode failed")
	}

	if p.Type != "PRIVATE KEY" && p.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("not private: %q", p.Type)
	}

	pk, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		return nil, err
	}

	// TODO: probably want an interface for this
	h := sha256.Sum256(payload)
	var signature []byte
	switch k := pk.(type) {
	case *rsa.PrivateKey:
		signature, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
	case *ecdsa.PrivateKey:
		signature, err = ecdsa.SignASN1(rand.Reader, k, h[:])
	case ed25519.PrivateKey:
		signature = ed25519.Sign(k, payload)
	}
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func pushIndex(ref name.Reference) (string, error) {
	get, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", err
	}

	desc := get.Descriptor

	b, err := json.Marshal(desc)
	if err != nil {
		return "", err
	}

	signature, err := sign(b)
	if err != nil {
		return "", err
	}

	l := &staticLayer{
		b:  b,
		mt: types.OCIContentDescriptor,
	}

	idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
		Add: l,
		Descriptor: v1.Descriptor{
			Annotations: map[string]string{
				"TODO": base64.StdEncoding.EncodeToString(signature),
			},
		},
	})

	// sha256:... -> sha256-...
	munged := strings.ReplaceAll(desc.Digest.String(), ":", "-")
	tag := ref.Context().Tag(munged)

	if err := remote.WriteIndex(tag, idx, remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		return "", err
	}

	return tag.String(), nil
}

type staticLayer struct {
	b  []byte
	mt types.MediaType
}

func (l *staticLayer) Digest() (v1.Hash, error) {
	h, _, err := v1.SHA256(bytes.NewReader(l.b))
	return h, err
}

// DiffID returns the Hash of the uncompressed layer.
func (l *staticLayer) DiffID() (v1.Hash, error) {
	h, _, err := v1.SHA256(bytes.NewReader(l.b))
	return h, err
}

// Compressed returns an io.ReadCloser for the compressed layer contents.
func (l *staticLayer) Compressed() (io.ReadCloser, error) {
	return ioutil.NopCloser(bytes.NewReader(l.b)), nil
}

// Uncompressed returns an io.ReadCloser for the uncompressed layer contents.
func (l *staticLayer) Uncompressed() (io.ReadCloser, error) {
	return ioutil.NopCloser(bytes.NewReader(l.b)), nil
}

// Size returns the compressed size of the Layer.
func (l *staticLayer) Size() (int64, error) {
	return int64(len(l.b)), nil
}

// MediaType returns the media type of the Layer.
func (l *staticLayer) MediaType() (types.MediaType, error) {
	return l.mt, nil
}
