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
	n := &mkCursor{
		mk:     mk,
		target: target,
		index:  0,
	}
	return n.Next()
}

// mkCursor acts as a cursor for the multiKeychain.
//
// Each keychain has the ability to Resolve() a single Authenticator.
// We can't return that Authenticator directly without losing our cursor, so we
// wrap it in an mkCursor, which maintains the index for our mk.keychains.
//
// For most wrapped Authenticators, calling Next() will result in mkCursor
// calling Resolve() on the next keychain.
//
// However, if an Authenticator happens to implement Next() already, mkCursor
// will call that Next() and return a new mkCursor that wraps it.
//
// This allows callers to iterate over both chains of Authenticators that
// implement Next() and chains of Keychains from multiKeychain.
//
// Like with multiKeychain.Resolve, mkCursor.Next() will skip over Anonymous and
// call Resolve on the next Keychain.
type mkCursor struct {
	mk      *multiKeychain
	target  Resource
	index   int
	wrapped Authenticator
}

type hasNext interface {
	Next() (Authenticator, error)
}

func (m *mkCursor) Next() (Authenticator, error) {
	if hn, ok := m.wrapped.(hasNext); ok {
		next, err := hn.Next()
		if next != Anonymous {
			return &mkCursor{
				mk:      m.mk,
				target:  m.target,
				index:   m.index,
				wrapped: next,
			}, err
		}
	}
	for i := m.index; i < len(m.mk.keychains); i += 1 {
		kc := m.mk.keychains[i]
		next := &mkCursor{
			mk:     m.mk,
			target: m.target,
			index:  i + 1,
		}
		auth, err := kc.Resolve(m.target)
		if err != nil {
			return next, err
		}
		if auth != Anonymous {
			next.wrapped = auth
			return next, nil
		}
	}
	return Anonymous, nil
}

func (m *mkCursor) Authorization() (*AuthConfig, error) {
	if m.wrapped == nil {
		// Avoid panicking here in case Next() err is unchecked.
		return Anonymous.Authorization()
	}
	return m.wrapped.Authorization()
}
