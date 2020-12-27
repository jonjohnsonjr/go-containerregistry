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

package tarball

import "github.com/google/go-containerregistry/pkg/v1/partial"

// LayerFromFile returns a v1.Layer given a tarball
// Deprecated: This caused dependency graph issues, use partial.LayerFromFile.
var LayerFromFile = partial.LayerFromFile

// LayerFromOpener returns a v1.Layer given an Opener function.
// The Opener may return either an uncompressed tarball (common),
// or a compressed tarball (uncommon).
//
// When using this in conjunction with something like remote.Write
// the uncompressed path may end up gzipping things multiple times:
//  1. Compute the layer SHA256
//  2. Upload the compressed layer.
// Since gzip can be expensive, we support an option to memoize the
// compression that can be passed here: tarball.WithCompressedCaching
// Deprecated: This caused dependency graph issues, use partial.LayerFromOpener.
var LayerFromOpener = partial.LayerFromOpener

// LayerFromReader returns a v1.Layer given a io.Reader.
// Deprecated: This caused dependency graph issues, use partial.LayerFromReader.
var LayerFromReader = partial.LayerFromReader

// LayerOption applies options to layer
// Deprecated: This caused dependency graph issues, use partial.LayerOption.
type LayerOption = partial.LayerOption

// WithCompressionLevel is a functional option for overriding the default
// compression level used for compressing uncompressed tarballs.
// Deprecated: This caused dependency graph issues, use partial.WithCompressionLevel.
var WithCompressionLevel = partial.WithCompressionLevel

// WithCompressedCaching is a functional option that overrides the
// logic for accessing the compressed bytes to memoize the result
// and avoid expensive repeated gzips.
// Deprecated: This caused dependency graph issues, use partial.WithCompressedCaching.
var WithCompressedCaching = partial.WithCompressedCaching

// WithEstargzOptions is a functional option that allow the caller to pass
// through estargz.Options to the underlying compression layer.  This is
// only meaningful when estargz is enabled.
// Deprecated: This caused dependency graph issues, use partial.WithEstargzOptions.
var WithEstargzOptions = partial.WithEstargzOptions

// WithEstargz is a functional option that explicitly enables estargz support.
// Deprecated: This caused dependency graph issues, use partial.WithEstargz.
var WithEstargz = partial.WithEstargz
