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
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/spf13/cobra"
)

func init() { Root.AddCommand(NewCmdAuth()) }

// NewCmdAuth creates a new cobra.Command for the auth subcommand.
func NewCmdAuth() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "auth",
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Usage()
		},
	}
	cmd.AddCommand(NewCmdAuthGet(), NewCmdAuthLogin())
	return cmd
}

func NewCmdAuthGet() *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Implements a credential helper",
		Args:  cobra.NoArgs,
		Run: func(_ *cobra.Command, args []string) {
			b, err := ioutil.ReadAll(os.Stdin)
			if err != nil {
				log.Fatal(err)
			}
			reg, err := name.NewRegistry(strings.TrimSpace(string(b)))
			if err != nil {
				log.Fatal(err)
			}
			auther, err := authn.DefaultKeychain.Resolve(reg)
			if err != nil {
				log.Fatal(err)
			}
			auth, err := auther.Authorization()
			if err != nil {
				log.Fatal(err)
			}
			if err := json.NewEncoder(os.Stdout).Encode(auth); err != nil {
				log.Fatal(err)
			}
		},
	}
}

func NewCmdAuthLogin() *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Implements a credential helper",
		Args:  cobra.NoArgs,
		Run: func(_ *cobra.Command, args []string) {
			b, err := ioutil.ReadAll(os.Stdin)
			if err != nil {
				log.Fatal(err)
			}
			reg, err := name.NewRegistry(strings.TrimSpace(string(b)))
			if err != nil {
				log.Fatal(err)
			}
			auther, err := authn.DefaultKeychain.Resolve(reg)
			if err != nil {
				log.Fatal(err)
			}
			auth, err := auther.Authorization()
			if err != nil {
				log.Fatal(err)
			}
			if err := json.NewEncoder(os.Stdout).Encode(auth); err != nil {
				log.Fatal(err)
			}
		},
	}
}
