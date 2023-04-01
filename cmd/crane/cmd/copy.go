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
	"runtime"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/spf13/cobra"
)

// NewCmdCopy creates a new cobra.Command for the copy subcommand.
func NewCmdCopy(options *[]crane.Option) *cobra.Command {
	allTags := false
	force := false
	jobs := runtime.GOMAXPROCS(0)
	cmd := &cobra.Command{
		Use:     "copy SRC DST",
		Aliases: []string{"cp"},
		Short:   "Efficiently copy a remote image from src to dst while retaining the digest value",
		Args:    cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			src, dst := args[0], args[1]
			if allTags {
				opts := append(*options, crane.WithJobs(jobs), crane.WithForce(force))
				return crane.CopyRepository(src, dst, opts...)
			}

			return crane.Copy(src, dst, *options...)
		},
	}

	cmd.Flags().BoolVarP(&allTags, "all-tags", "a", false, "(Optional) if true, copy all tags from SRC to DST")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "(Optional) if true, allow overwriting existing tags")
	cmd.Flags().IntVarP(&jobs, "jobs", "j", runtime.GOMAXPROCS(0), "The maximum number of concurrent copies")

	return cmd
}
