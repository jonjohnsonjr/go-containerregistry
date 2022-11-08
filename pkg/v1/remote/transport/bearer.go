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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"

	authchallenge "github.com/docker/distribution/registry/client/auth/challenge"
	"github.com/google/go-containerregistry/internal/redact"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
)

// Some registries don't have "token" in the response. See #54.
type TokenResponse struct {
	Token        string `json:"token"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// NewBearer returns a bearer transport and the registry TokenResponse for reuse.
func NewBearer(ctx context.Context, pr *PingResp, reg name.Registry, auth authn.Authenticator, t http.RoundTripper, scopes []string) (*Wrapper, *TokenResponse, error) {
	// We require the realm, which tells us where to send our Basic auth to turn it into Bearer auth.
	realm, ok := pr.Parameters["realm"]
	if !ok {
		realm = reg.RegistryStr()
	}
	service := pr.Parameters["service"]
	bt := &bearerTransport{
		inner:    t,
		basic:    auth,
		realm:    realm,
		registry: reg,
		service:  service,
		scopes:   scopes,
		scheme:   pr.Scheme,
	}
	authcfg, err := auth.Authorization()
	if err != nil {
		return nil, nil, err
	}
	tok, err := bt.Refresh(ctx, authcfg)
	if err != nil {
		return nil, nil, err
	}
	if tok.Token != "" {
		bt.bearer.RegistryToken = tok.Token
	}
	return &Wrapper{bt}, tok, nil
}

// OldBearer returns a bearer transport based on a cached TokenResponse (see NewBearer).
func OldBearer(pr *PingResp, tok *TokenResponse, reg name.Registry, auth authn.Authenticator, t http.RoundTripper, scopes []string) (*Wrapper, error) {
	// We require the realm, which tells us where to send our Basic auth to turn it into Bearer auth.
	realm, ok := pr.Parameters["realm"]
	if !ok {
		realm = reg.RegistryStr()
	}
	service := pr.Parameters["service"]
	bt := &bearerTransport{
		inner:    t,
		basic:    auth,
		realm:    realm,
		registry: reg,
		service:  service,
		scopes:   scopes,
		scheme:   pr.Scheme,
	}
	// Some registries set access_token instead of token.
	if tok.AccessToken != "" {
		tok.Token = tok.AccessToken
	}

	// Find a token to turn into a Bearer authenticator
	if tok.Token != "" {
		bt.bearer.RegistryToken = tok.Token
	}

	// If we obtained a refresh token from the oauth flow, use that for refresh() now.
	if tok.RefreshToken != "" {
		bt.basic = authn.FromConfig(authn.AuthConfig{
			IdentityToken: tok.RefreshToken,
		})
	}
	return &Wrapper{bt}, nil
}

type bearerTransport struct {
	// Wrapped by bearerTransport.
	inner http.RoundTripper
	// Basic credentials that we exchange for bearer tokens.
	basic authn.Authenticator
	// Holds the bearer response from the token service.
	bearer authn.AuthConfig
	// Registry to which we send bearer tokens.
	registry name.Registry
	// See https://tools.ietf.org/html/rfc6750#section-3
	realm string
	// See https://docs.docker.com/registry/spec/auth/token/
	service string
	scopes  []string
	// Scheme we should use, determined by ping response.
	scheme string
}

var _ http.RoundTripper = (*bearerTransport)(nil)

var portMap = map[string]string{
	"http":  "80",
	"https": "443",
}

func stringSet(ss []string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, s := range ss {
		set[s] = struct{}{}
	}
	return set
}

// RoundTrip implements http.RoundTripper
func (bt *bearerTransport) RoundTrip(in *http.Request) (*http.Response, error) {
	sendRequest := func() (*http.Response, error) {
		// http.Client handles redirects at a layer above the http.RoundTripper
		// abstraction, so to avoid forwarding Authorization headers to places
		// we are redirected, only set it when the authorization header matches
		// the registry with which we are interacting.
		// In case of redirect http.Client can use an empty Host, check URL too.
		if matchesHost(bt.registry, in, bt.scheme) {
			hdr := fmt.Sprintf("Bearer %s", bt.bearer.RegistryToken)
			in.Header.Set("Authorization", hdr)
		}
		return bt.inner.RoundTrip(in)
	}

	res, err := sendRequest()
	if err != nil {
		return nil, err
	}

	// If we hit a WWW-Authenticate challenge, it might be due to expired tokens or insufficient scope.
	if challenges := authchallenge.ResponseChallenges(res); len(challenges) != 0 {
		res.Body.Close()
		newScopes := []string{}
		for _, wac := range challenges {
			// TODO(jonjohnsonjr): Should we also update "realm" or "service"?
			if want, ok := wac.Parameters["scope"]; ok {
				// Add any scopes that we don't already request.
				got := stringSet(bt.scopes)
				if _, ok := got[want]; !ok {
					newScopes = append(newScopes, want)
				}
			}
		}

		// Some registries seem to only look at the first scope parameter during a token exchange.
		// If a request fails because it's missing a scope, we should put those at the beginning,
		// otherwise the registry might just ignore it :/
		newScopes = append(newScopes, bt.scopes...)
		bt.scopes = newScopes

		// TODO(jonjohnsonjr): Teach transport.Error about "error" and "error_description" from challenge.

		// Retry the request to attempt to get a valid token.
		if err = bt.refresh(in.Context()); err != nil {
			return nil, err
		}
		return sendRequest()
	}

	return res, err
}

// It's unclear which authentication flow to use based purely on the protocol,
// so we rely on heuristics and fallbacks to support as many registries as possible.
// The basic token exchange is attempted first, falling back to the oauth flow.
// If the IdentityToken is set, this indicates that we should start with the oauth flow.
func (bt *bearerTransport) refresh(ctx context.Context) error {
	auth, err := bt.basic.Authorization()
	if err != nil {
		return err
	}

	if auth.RegistryToken != "" {
		bt.bearer.RegistryToken = auth.RegistryToken
		return nil
	}

	response, err := bt.Refresh(ctx, auth)
	if err != nil {
		return err
	}

	// Some registries set access_token instead of token.
	if response.AccessToken != "" {
		response.Token = response.AccessToken
	}

	// Find a token to turn into a Bearer authenticator
	if response.Token != "" {
		bt.bearer.RegistryToken = response.Token
	}

	// If we obtained a refresh token from the oauth flow, use that for refresh() now.
	if response.RefreshToken != "" {
		bt.basic = authn.FromConfig(authn.AuthConfig{
			IdentityToken: response.RefreshToken,
		})
	}

	return nil
}

func (bt *bearerTransport) Refresh(ctx context.Context, auth *authn.AuthConfig) (*TokenResponse, error) {
	var (
		content []byte
		err     error
	)
	if auth.IdentityToken != "" {
		// If the secret being stored is an identity token,
		// the Username should be set to <token>, which indicates
		// we are using an oauth flow.
		content, err = bt.refreshOauth(ctx)
		var terr *Error
		if errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound {
			// Note: Not all token servers implement oauth2.
			// If the request to the endpoint returns 404 using the HTTP POST method,
			// refer to Token Documentation for using the HTTP GET method supported by all token servers.
			content, err = bt.refreshBasic(ctx)
		}
	} else {
		content, err = bt.refreshBasic(ctx)
	}
	if err != nil {
		return nil, err
	}

	var response TokenResponse
	if err := json.Unmarshal(content, &response); err != nil {
		return nil, err
	}

	if response.Token == "" && response.AccessToken == "" {
		return &response, fmt.Errorf("no token in bearer response:\n%s", content)
	}

	return &response, nil
}

func matchesHost(reg name.Registry, in *http.Request, scheme string) bool {
	canonicalHeaderHost := canonicalAddress(in.Host, scheme)
	canonicalURLHost := canonicalAddress(in.URL.Host, scheme)
	canonicalRegistryHost := canonicalAddress(reg.RegistryStr(), scheme)
	return canonicalHeaderHost == canonicalRegistryHost || canonicalURLHost == canonicalRegistryHost
}

func canonicalAddress(host, scheme string) (address string) {
	// The host may be any one of:
	// - hostname
	// - hostname:port
	// - ipv4
	// - ipv4:port
	// - ipv6
	// - [ipv6]:port
	// As net.SplitHostPort returns an error if the host does not contain a port, we should only attempt
	// to call it when we know that the address contains a port
	if strings.Count(host, ":") == 1 || (strings.Count(host, ":") >= 2 && strings.Contains(host, "]:")) {
		hostname, port, err := net.SplitHostPort(host)
		if err != nil {
			return host
		}
		if port == "" {
			port = portMap[scheme]
		}

		return net.JoinHostPort(hostname, port)
	}

	return net.JoinHostPort(host, portMap[scheme])
}

// https://docs.docker.com/registry/spec/auth/oauth/
func (bt *bearerTransport) refreshOauth(ctx context.Context) ([]byte, error) {
	auth, err := bt.basic.Authorization()
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(bt.realm)
	if err != nil {
		return nil, err
	}

	v := url.Values{}
	v.Set("scope", strings.Join(bt.scopes, " "))
	if bt.service != "" {
		v.Set("service", bt.service)
	}
	v.Set("client_id", defaultUserAgent)
	if auth.IdentityToken != "" {
		v.Set("grant_type", "refresh_token")
		v.Set("refresh_token", auth.IdentityToken)
	} else if auth.Username != "" && auth.Password != "" {
		// TODO(#629): This is unreachable.
		v.Set("grant_type", "password")
		v.Set("username", auth.Username)
		v.Set("password", auth.Password)
		v.Set("access_type", "offline")
	}

	client := http.Client{Transport: bt.inner}
	req, err := http.NewRequest(http.MethodPost, u.String(), strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// We don't want to log credentials.
	ctx = redact.NewContext(ctx, "oauth token response contains credentials")

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := CheckError(resp, http.StatusOK); err != nil {
		logs.Warn.Printf("No matching credentials were found for %q", bt.registry)
		return nil, err
	}

	return ioutil.ReadAll(resp.Body)
}

// https://docs.docker.com/registry/spec/auth/token/
func (bt *bearerTransport) refreshBasic(ctx context.Context) ([]byte, error) {
	u, err := url.Parse(bt.realm)
	if err != nil {
		return nil, err
	}
	b := &basicTransport{
		inner:  bt.inner,
		auth:   bt.basic,
		target: u.Host,
	}
	client := http.Client{Transport: b}

	v := u.Query()
	v["scope"] = bt.scopes
	v.Set("service", bt.service)
	u.RawQuery = v.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	// We don't want to log credentials.
	ctx = redact.NewContext(ctx, "basic token response contains credentials")

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := CheckError(resp, http.StatusOK); err != nil {
		logs.Warn.Printf("No matching credentials were found for %q", bt.registry)
		return nil, err
	}

	return ioutil.ReadAll(resp.Body)
}
