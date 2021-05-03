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

package cmd

import (
	"fmt"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/spf13/cobra"
)

// NewCmdUpload creates a new cobra.Command for the upload subcommand.
func NewCmdUpload(options *[]crane.Option) *cobra.Command {
	var (
		blob      string
		mediaType string
	)

	uploadCmd := &cobra.Command{
		Use:   "upload",
		Short: "Upload contents of a file to a remote registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			ref, err := crane.Upload(blob, args[0], *options...)
			if err != nil {
				return err
			}
			fmt.Println(ref)
			return nil
		},
	}
	uploadCmd.Flags().StringVarP(&blob, "", "f", "-", "Path to blob to upload")
	uploadCmd.Flags().StringVarP(&mediaType, "media-type", "m", "", "")
	return uploadCmd
}
