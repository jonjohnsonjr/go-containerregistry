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

package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	_ "github.com/motemen/go-loghttp/global"
)

func main() {
	for i := 0; i <= 400; i++ {
		dst := fmt.Sprintf("gcr.io/jonjohnson-test/bench/run:%d", i)
		dstTag, err := name.NewTag(dst, name.WeakValidation)
		if err != nil {
			log.Fatalf("parsing tag %q: %v", dst, err)
		}

		// Image with 5 random 1KB layers.
		img, err := random.Image(1024, 5)
		if err != nil {
			log.Fatalf("random.Image: %v", err)
		}

		auth, err := authn.DefaultKeychain.Resolve(dstTag.Context().Registry)
		if err != nil {
			log.Fatalf("auth: %v", err)
		}

		start := time.Now()
		if err := remote.Write(dstTag, img, auth, http.DefaultTransport); err != nil {
			log.Fatalf("writing image %q: %v", dstTag, err)
		}
		elapsed := time.Since(start)
		fmt.Println(int64(elapsed / time.Millisecond))
	}
}
