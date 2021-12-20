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
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/spf13/cobra"
)

// NewCmdPush creates a new cobra.Command for the push subcommand.
func NewCmdPush(options *[]crane.Option) *cobra.Command {
	index := false
	cmd := &cobra.Command{
		Use:   "push PATH IMAGE",
		Short: "Push local image contents to a remote registry",
		Long:  `If the PATH is a directory, it will be read as an OCI image layout. Otherwise, PATH is assumed to be a docker-style tarball.`,
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			path, tag := args[0], args[1]

			img, err := loadImage(path, index)
			if err != nil {
				return err
			}

			return crane.Push(img, tag, *options...)
		},
	}
	cmd.Flags().BoolVar(&index, "index", false, "Push the collection of images as a single index")
	return cmd
}

func loadImage(path string, index bool) (crane.Pushable, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !stat.IsDir() {
		img, err := crane.Load(path)
		if err != nil {
			return nil, fmt.Errorf("loading %s as tarball: %w", path, err)
		}
		return img, nil
	}

	l, err := layout.FromPath(path)
	if err != nil {
		return nil, fmt.Errorf("loading %s as OCI layout: %w", path, err)
	}

	if index {
		return l.ImageIndex()
	}

	manifests, err := l.Manifests()
	if err != nil {
		return nil, err
	}
	if len(manifests) != 1 {
		// TODO: Figure out how to support a flag to push each entry separately.
		return nil, fmt.Errorf("layout contains multiple entries, see --index")
	}

	if m, ok := manifests[0].(crane.Pushable); ok {
		return m, nil
	}

	return nil, fmt.Errorf("layout does not contain an image, see --index")
}
