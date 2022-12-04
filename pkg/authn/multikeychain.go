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

package authn

type multiKeychain struct {
	keychains []Keychain
}

// Assert that our multi-keychain implements Keychain.
var _ (Keychain) = (*multiKeychain)(nil)

// NewMultiKeychain composes a list of keychains into one new keychain.
func NewMultiKeychain(kcs ...Keychain) Keychain {
	return &multiKeychain{keychains: kcs}
}

// Resolve implements Keychain.
func (mk *multiKeychain) Resolve(target Resource) (Authenticator, error) {
	n := &mkNext{
		mk:     mk,
		target: target,
		index:  0,
	}
	return n.Next()
}

type mkNext struct {
	mk      *multiKeychain
	target  Resource
	index   int
	wrapped Authenticator
}

type hasNext interface {
	Next() (Authenticator, error)
}

func (m *mkNext) Next() (Authenticator, error) {
	if hn, ok := m.wrapped.(hasNext); ok {
		next, err := hn.Next()
		if next != Anonymous {
			return &mkNext{
				mk:      m.mk,
				target:  m.target,
				index:   m.index,
				wrapped: next,
			}, err
		}
	}
	for i := m.index; i < len(m.mk.keychains); i += 1 {
		kc := m.mk.keychains[i]
		next := &mkNext{
			mk:     m.mk,
			target: m.target,
			index:  i + 1,
		}
		auth, err := kc.Resolve(m.target)
		if err != nil {
			// TODO: discuss -- this allows callers to handle errors and continue
			return next, err
		}
		if auth != Anonymous {
			next.wrapped = auth
			return next, nil
		}
	}
	return Anonymous, nil
}

func (m *mkNext) Authorization() (*AuthConfig, error) {
	return m.wrapped.Authorization()
}
