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

import (
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
)

func TestMultiKeychain(t *testing.T) {
	one := &Basic{Username: "one", Password: "secret"}
	two := &Basic{Username: "two", Password: "secret"}
	three := &Basic{Username: "three", Password: "secret"}
	four := &Basic{Username: "four", Password: "secret"}

	regOne, _ := name.NewRegistry("one.gcr.io", name.StrictValidation)
	regTwo, _ := name.NewRegistry("two.gcr.io", name.StrictValidation)
	regThree, _ := name.NewRegistry("three.gcr.io", name.StrictValidation)

	tests := []struct {
		name string
		reg  name.Registry
		kc   Keychain
		want []Authenticator
	}{{
		// Make sure our test keychain WAI
		name: "simple fixed test (match)",
		reg:  regOne,
		kc:   fixedKeychain{regOne: one},
		want: []Authenticator{one},
	}, {
		// Make sure our test keychain WAI
		name: "simple fixed test (no match)",
		reg:  regTwo,
		kc:   fixedKeychain{regOne: one},
		want: []Authenticator{Anonymous},
	}, {
		name: "match first and second keychain",
		reg:  regOne,
		kc: NewMultiKeychain(
			fixedKeychain{regOne: one},
			fixedKeychain{regOne: three, regTwo: two},
		),
		want: []Authenticator{one, three},
	}, {
		name: "match second keychain",
		reg:  regTwo,
		kc: NewMultiKeychain(
			fixedKeychain{regOne: one},
			fixedKeychain{regOne: three, regTwo: two},
		),
		want: []Authenticator{two},
	}, {
		name: "match no keychain",
		reg:  regThree,
		kc: NewMultiKeychain(
			fixedKeychain{regOne: one},
			fixedKeychain{regOne: three, regTwo: two},
		),
		want: []Authenticator{Anonymous},
	}, {
		name: "match first and second keychain and an error then next",
		reg:  regOne,
		kc: NewMultiKeychain(
			fixedKeychain{regOne: one},
			&errKeychain{errors.New("this is an error")},
			fixedKeychain{regOne: &chainedAuth{three, four}, regTwo: two},
		),
		want: []Authenticator{one, Anonymous, three, four},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.kc.Resolve(test.reg)
			if err != nil {
				t.Errorf("Resolve() = %v", err)
			}
			for _, want := range test.want {
				gotAuth, err := got.Authorization()
				if err != nil {
					t.Errorf("Authorization() = %v", err)
				}
				wantAuth, err := want.Authorization()
				if err != nil {
					t.Errorf("Authorization() = %v", err)
				}
				if *gotAuth != *wantAuth {
					t.Errorf("Resolve() = %v, wanted %v", gotAuth, wantAuth)
				}

				wn, ok := got.(interface {
					Next() (Authenticator, error)
				})
				if ok {
					got, err = wn.Next()
					if err != nil {
						if got == nil {
							t.Fatalf("Next() = %v", err)
						}
					}
				}
			}
		})
	}
}

type fixedKeychain map[Resource]Authenticator

var _ Keychain = (fixedKeychain)(nil)

// Resolve implements Keychain.
func (fk fixedKeychain) Resolve(target Resource) (Authenticator, error) {
	if auth, ok := fk[target]; ok {
		return auth, nil
	}
	return Anonymous, nil
}

type chainedAuth struct {
	auth Authenticator
	next Authenticator
}

func (c *chainedAuth) Authorization() (*AuthConfig, error) {
	return c.auth.Authorization()
}

// Allows falling back to anonymous even if we did find creds.
func (c *chainedAuth) Next() (Authenticator, error) {
	return c.next, nil
}

type errKeychain struct {
	err error
}

var _ Keychain = (*errKeychain)(nil)

// Resolve implements Keychain.
func (e *errKeychain) Resolve(target Resource) (Authenticator, error) {
	return nil, e.err
}
