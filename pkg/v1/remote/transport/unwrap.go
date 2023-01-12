// Copyright 2023 Google LLC All Rights Reserved.
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

package transport

import (
	"net/http"
	"reflect"
)

// Is is the transport equivalent of errors.Is.
func Is(t, target http.RoundTripper) bool {
	if target == nil {
		return t == target
	}
	for {
		if reflect.TypeOf(t) == reflect.TypeOf(target) {
			return true
		}
		if x, ok := t.(interface{ Is(http.RoundTripper) bool }); ok && x.Is(target) {
			return true
		}
		// TODO: consider supporting target.Is(t). This would allow
		// user-definable predicates, but also may allow for coping with sloppy
		// APIs, thereby making it easier to get away with them.
		if t = Unwrap(t); t == nil {
			return false
		}
	}

}

// Unwrap is the transport equivalent of errors.Unwrap.
func Unwrap(t http.RoundTripper) http.RoundTripper {
	u, ok := t.(interface {
		Unwrap() http.RoundTripper
	})
	if !ok {
		return nil
	}
	return u.Unwrap()
}
