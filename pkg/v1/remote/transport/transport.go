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

package transport

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/auth/challenge"
	"github.com/docker/distribution/registry/client/transport"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

const (
	transportName = "go-containerregistry"
)

// New returns a new RoundTripper based on the provided RoundTripper that has been
// setup to authenticate with the remote registry "reg", in the capacity
// laid out by the specified scopes.
func New(reg name.Registry, auther authn.Authenticator, t http.RoundTripper, scopes []string) (http.RoundTripper, error) {
	// The handshake:
	//  1. Use "t" to ping() the registry for the authentication challenge.
	//
	//  2a. If we get back a 200, then simply use "t".
	//
	//  2b. If we get back a 401 with a Basic challenge, then use a transport
	//     that just attachs auth each roundtrip.
	//
	//  2c. If we get back a 401 with a Bearer challenge, then use a transport
	//     that attaches a bearer token to each request, and refreshes is on 401s.
	//     Perform an initial refresh to seed the bearer token.

	// First we ping the registry to determine the parameters of the authentication handshake
	// (if one is even necessary).
	client := http.Client{Transport: t}

	// This first attempts to use "https" for every request, falling back to http
	// if the registry matches our localhost heuristic or if it is intentionally
	// set to insecure via name.NewInsecureRegistry.
	schemes := []string{"https"}
	if reg.Scheme() == "http" {
		schemes = append(schemes, "http")
	}

	var connErr error
	for _, scheme := range schemes {
		url := fmt.Sprintf("%s://%s/v2/", scheme, reg.Name())
		resp, err := client.Get(url)
		if err != nil {
			connErr = err
			// Potentially retry with http.
			continue
		}
		defer resp.Body.Close()

		challengeManager := challenge.NewSimpleManager()
		if err := challengeManager.AddResponse(resp); err != nil {
			return nil, err
		}

		authConfig, err := auther.Authorization()
		if err != nil {
			return nil, err
		}
		creds := loginCredentialStore{authConfig}

		tokenHandlerOptions := auth.TokenHandlerOptions{
			Transport:     t,
			Credentials:   creds,
			OfflineAccess: true,
			ClientID:      transportName,
			Scopes:        convertScopes(scopes),
		}
		tokenHandler := auth.NewTokenHandlerWithOptions(tokenHandlerOptions)
		basicHandler := auth.NewBasicHandler(creds)
		mod := auth.NewAuthorizer(challengeManager, tokenHandler, basicHandler)

		return &remoteTransport{
			inner: transport.NewTransport(t, mod),
		}, nil
	}
	return nil, connErr
}

var _ http.RoundTripper = (*remoteTransport)(nil)

type remoteTransport struct {
	// Wrapped by remoteTransport.
	inner http.RoundTripper
}

func (t *remoteTransport) RoundTrip(in *http.Request) (*http.Response, error) {
	in.Header.Set("User-Agent", transportName)
	return t.inner.RoundTrip(in)
}

type loginCredentialStore struct {
	authConfig *authn.AuthConfig
}

func (lcs loginCredentialStore) Basic(*url.URL) (string, string) {
	return lcs.authConfig.Username, lcs.authConfig.Password
}

func (lcs loginCredentialStore) RefreshToken(*url.URL, string) string {
	return lcs.authConfig.IdentityToken
}

func (lcs loginCredentialStore) SetRefreshToken(_ *url.URL, _, token string) {
	lcs.authConfig.IdentityToken = token
}

type stringer struct {
	s string
}

func (s stringer) String() string {
	return s.s
}

func convertScopes(ss []string) []auth.Scope {
	stringers := make([]auth.Scope, len(ss))
	for i, s := range ss {
		stringers[i] = stringer{s}
	}
	return stringers
}
