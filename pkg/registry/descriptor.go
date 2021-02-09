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

package registry

import (
	"net/http"
	"strings"
)

func isDescriptor(req *http.Request) bool {
	elems := strings.Split(req.URL.Path, "/")
	elems = elems[1:]
	if len(elems) < 4 {
		return false
	}
	return elems[len(elems)-2] == "descriptors"
}

func (m *manifests) handleDesc(resp http.ResponseWriter, req *http.Request) *regError {
	// TODO: Pagination?
	elem := strings.Split(req.URL.Path, "/")
	elem = elem[1:]
	target := elem[len(elem)-1]
	repo := strings.Join(elem[1:len(elem)-2], "/")

	if target != "list" {
		return &regError{
			Status:  http.StatusNotImplemented,
			Code:    "TODO",
			Message: "Sorry",
		}
	}

	c, ok := m.manifests[repo]
	if !ok {
		return &regError{
			Status:  http.StatusNotFound,
			Code:    "NAME_UNKNOWN",
			Message: "Unknown name",
		}
	}

	return nil
}
