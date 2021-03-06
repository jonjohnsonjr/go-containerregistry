#!/bin/bash

# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o nounset
set -o pipefail

# Trying to compile without the build tag should work.
go test ./pkg/name/internal

# Actually trying to compile should fail.
go test -tags=compile ./pkg/name/internal
if [[ $? -eq 0 ]]; then
  echo "pkg/name/internal test compiled successfully, expected failure"
  exit 1
fi
echo "pkg/name/internal test successfully did not compile"
