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
	"net/http"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// TODO: Adopt standard flags for this stuff, maybe use cobra.
// TODO: Different kinds of signatures.
var keyPath = flag.String("key", "", "private key")
var annotation = flag.String("a", "", "annotation")
var verbose = flag.Bool("v", false, "log lots of stuff")

const sigkey = "dev.ggcr.crane/signature"

func main() {
	flag.Parse()

	logs.Progress.SetOutput(os.Stderr)
	logs.Warn.SetOutput(os.Stderr)
	if *verbose {
		logs.Debug.SetOutput(os.Stderr)
	}

	ref, err := name.ParseReference(flag.Args()[1])
	if err != nil {
		log.Fatal(err)
	}

	subcommand := flag.Args()[0]
	if subcommand == "sign" {
		output, err := pushIndex(ref)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(output)
	} else if subcommand == "verify" {
		err := verifyIndex(ref)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Verified OK")
	} else {
		log.Fatalf("unexpected subcommand: %s", subcommand)
	}
}

func sign(payload []byte) ([]byte, error) {
	b, err := ioutil.ReadFile(*keyPath)
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, errors.New("pem.Decode failed")
	}

	if p.Type != "PRIVATE KEY" {
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

func verify(base64sig string, payload []byte) error {
	signature, err := base64.StdEncoding.DecodeString(base64sig)
	if err != nil {
		return err
	}

	b, err := ioutil.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return errors.New("pem.Decode failed")
	}

	if p.Type != "PUBLIC KEY" {
		return fmt.Errorf("not public: %q", p.Type)
	}

	pk, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		return err
	}

	// TODO: probably want an interface for this
	h := sha256.Sum256(payload)
	switch k := pk.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], signature)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, h[:], signature) {
			return errors.New("unable to verify whatever")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(k, payload, signature) {
			return errors.New("unable to verify whatever")
		}
	default:
		return fmt.Errorf("invalid public key type: %T", k)
	}

	return nil
}

func verifyIndex(ref name.Reference) error {
	// Find the magic tag that points to the signatures.
	var idxRef name.Reference
	if tag, ok := ref.(name.Tag); ok {
		desc, err := remote.Get(tag, remote.WithAuthFromKeychain(authn.DefaultKeychain))
		if err != nil {
			return err
		}
		munged := strings.ReplaceAll(desc.Digest.String(), ":", "-")
		idxRef = ref.Context().Tag(munged)
	} else if dgst, ok := ref.(name.Digest); ok {
		munged := strings.ReplaceAll(dgst.Identifier(), ":", "-")
		idxRef = ref.Context().Tag(munged)
	}

	idx, err := remote.Index(idxRef, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return err
	}
	m, err := idx.IndexManifest()
	if err != nil {
		return err
	}

	// Emit any signed payloads (descriptors) to stdout for jq parsing.
	// If we don't find any signed payloads, return an error.
	// If any signatures don't validate, return an error.
	verified := false
	errs := []string{}
	for _, desc := range m.Manifests {
		base64sig, ok := desc.Annotations[sigkey]
		if !ok {
			continue
		}
		// TODO: get from desc?
		l, err := remote.Layer(ref.Context().Digest(desc.Digest.String()), remote.WithAuthFromKeychain(authn.DefaultKeychain))
		if err != nil {
			return err
		}

		r, err := l.Compressed()
		if err != nil {
			return err
		}

		payload, err := ioutil.ReadAll(r)
		if err != nil {
			return err
		}

		if err := verify(base64sig, payload); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		fmt.Println(string(payload))
		verified = true
	}
	if !verified {
		return fmt.Errorf("no matching signatures:\n%s", strings.Join(errs, "\n  "))
	}
	return nil
}

func pushIndex(ref name.Reference) (string, error) {
	get, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", err
	}

	desc := get.Descriptor

	if *annotation != "" {
		parts := strings.SplitN(*annotation, "=", 2)
		if len(parts) == 2 {
			if desc.Annotations == nil {
				desc.Annotations = map[string]string{}
			}
			desc.Annotations[parts[0]] = parts[1]
		}
	}
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

	// sha256:... -> sha256-...
	munged := strings.ReplaceAll(desc.Digest.String(), ":", "-")
	tag := ref.Context().Tag(munged)

	base, err := remote.Index(tag, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		if te, ok := err.(*transport.Error); ok {
			if te.StatusCode != http.StatusNotFound {
				return "", te
			} else {
				base = empty.Index
			}
		} else {
			return "", err
		}
	}

	idx := mutate.AppendManifests(base, mutate.IndexAddendum{
		Add: l,
		Descriptor: v1.Descriptor{
			Annotations: map[string]string{
				sigkey: base64.StdEncoding.EncodeToString(signature),
			},
		},
	})

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
