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
	"fmt"
	"log"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/spf13/cobra"
)

func init() { Root.AddCommand(NewCmdLabel()) }

// NewCmdLabel creates a new cobra.Command for the label subcommand.
func NewCmdLabel() *cobra.Command {
	var src, dst string
	labelCmd := &cobra.Command{
		Use:   "label IMAGE",
		Short: "Add labels to an image",
		Args:  cobra.MinimumNArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			if dst == "" {
				dst = src
			}

			labels := make(map[string]string)
			for _, arg := range args {
				parts := strings.SplitN(arg, "=", 2)
				if len(parts) != 2 {
					log.Fatalf(`wrong label syntax, expected "$key=$value", got: %s`, arg)
				}
				k, v := parts[0], parts[1]
				labels[k] = v
			}

			img, err := crane.Pull(src, options...)
			if err != nil {
				log.Fatal(err)
			}
			img, err = crane.Label(img, labels)
			if err != nil {
				log.Fatal(err)
			}

			dstRef, err := name.ParseReference(dst)
			if err != nil {
				log.Fatal(err)
			}
			if _, ok := dstRef.(name.Digest); ok {
				dgst, err := img.Digest()
				if err != nil {
					log.Fatal(err)
				}
				dst = dstRef.Context().Digest(dgst.String()).String()
			}

			if err := crane.Push(img, dst, options...); err != nil {
				log.Fatal(err)
			}
			fmt.Println(dst)
		},
	}
	labelCmd.Flags().StringVarP(&src, "image", "i", "", "Image to label")
	labelCmd.Flags().StringVarP(&dst, "output", "o", "", "Destination for image, defaults to --image")

	labelCmd.MarkFlagRequired("image")
	return labelCmd
}
