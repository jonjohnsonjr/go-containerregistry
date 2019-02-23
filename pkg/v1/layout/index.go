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

package layout

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

var _ v1.ImageIndex = (*layoutIndex)(nil)

type layoutIndex struct {
	path     string
	rawIndex []byte
}

func ImageIndex(path string) (v1.ImageIndex, error) {
	rawIndex, err := ioutil.ReadFile(filepath.Join(path, "index.json"))
	if err != nil {
		return nil, err
	}

	img := &layoutIndex{
		path:     path,
		rawIndex: rawIndex,
	}

	return img, nil
}

func (i *layoutIndex) MediaType() (types.MediaType, error) {
	return types.OCIImageIndex, nil
}

func (i *layoutIndex) Digest() (v1.Hash, error) {
	digest, _, err := v1.SHA256(bytes.NewReader(i.rawIndex))
	return digest, err
}

func (i *layoutIndex) IndexManifest() (*v1.IndexManifest, error) {
	var index v1.IndexManifest
	err := json.Unmarshal(i.rawIndex, &index)
	return &index, err
}

func (i *layoutIndex) RawIndexManifest() ([]byte, error) {
	return i.rawIndex, nil
}
