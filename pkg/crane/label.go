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

package crane

import (
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

// Label sets the labels on the given image.
func Label(img v1.Image, labels map[string]string, opt ...Option) (v1.Image, error) {
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("getting config file: %v")
	}

	if cf.Config.Labels == nil {
		cf.Config.Labels = make(map[string]string)
	}

	for k, v := range labels {
		cf.Config.Labels[k] = v
	}

	return mutate.ConfigFile(img, cf)
}
