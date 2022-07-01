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
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

func TestAuth(t *testing.T) {
	// Stupid coverage.
	cmd := NewCmdAuth()
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}
func TestAuthGet(t *testing.T) {
	cf := `{
	"auths": {
		"registry.example.com": {
			"username": "AzureDiamond",
			"identityToken": "hunter2"
		}
	}
}`

	dir := t.TempDir()
	os.Setenv("DOCKER_CONFIG", dir)
	if err := ioutil.WriteFile(filepath.Join(dir, "config.json"), []byte(cf), os.ModePerm); err != nil {
		t.Fatal(err)
	}

	buf := bytes.NewBuffer(nil)
	cmd := NewCmdAuthGet()
	cmd.SetIn(strings.NewReader("registry.example.com"))
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	creds := credentials{}
	if err := json.Unmarshal(buf.Bytes(), &creds); err != nil {
		t.Fatal(err)
	}
	if got, want := creds.Username, "<token>"; got != want {
		t.Errorf("Username: got %q, want %q", got, want)
	}
	if got, want := creds.Secret, "hunter2"; got != want {
		t.Errorf("Secret: got %q, want %q", got, want)
	}

	buf.Reset()
	cmd = NewCmdAuthGet()
	cmd.SetIn(strings.NewReader("registry2.example.com"))
	cmd.SetOut(buf)

	if err := cmd.Execute(); !errors.Is(err, errNoCreds) {
		t.Fatal(err)
	}
	if got, want := buf.String(), "credentials not found in native keychain\n"; got != want {
		t.Errorf("stdout: got %q, want %q", got, want)
	}
}

func TestAuthLogin(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("DOCKER_CONFIG", dir)

	reg, err := name.NewRegistry("registry.example.com")
	if err != nil {
		t.Fatal(err)
	}

	cmd := NewCmdAuthLogin()
	cmd.SetArgs([]string{
		"--username=AzureDiamond",
		"--password=hunter2",
		reg.String(),
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	authorizer, err := authn.DefaultKeychain.Resolve(reg)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := authorizer.Authorization()
	if err != nil {
		t.Fatal(err)
	}

	if got, want := creds.Username, "AzureDiamond"; got != want {
		t.Errorf("Username: got %q, want %q", got, want)
	}
	if got, want := creds.Password, "hunter2"; got != want {
		t.Errorf("Password: got %q, want %q", got, want)
	}

	dh, err := name.NewRegistry("docker.io")
	if err != nil {
		t.Fatal(err)
	}

	cmd = NewCmdAuthLogin()
	cmd.SetArgs([]string{
		"--username=AzureDiamond",
		"--password-stdin",
		dh.String(),
	})
	cmd.SetIn(strings.NewReader("hunter3"))
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	authorizer, err = authn.DefaultKeychain.Resolve(dh)
	if err != nil {
		t.Fatal(err)
	}
	creds, err = authorizer.Authorization()
	if err != nil {
		t.Fatal(err)
	}

	if got, want := creds.Username, "AzureDiamond"; got != want {
		t.Errorf("Username: got %q, want %q", got, want)
	}
	if got, want := creds.Password, "hunter3"; got != want {
		t.Errorf("Password: got %q, want %q", got, want)
	}
}

func TestAuthLoginError(t *testing.T) {
	cmd := NewCmdAuthLogin()
	cmd.SetArgs([]string{"example.com"})
	if err := cmd.Execute(); !errors.Is(err, errNoFlags) {
		t.Fatal(err)
	}
}
