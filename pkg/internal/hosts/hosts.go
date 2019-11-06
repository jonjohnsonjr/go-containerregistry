// Copyright 2019 Google LLC All Rights Reserved.
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

// Package hosts contains some small common code for dealing with hostnames.
package hosts

import (
	"net"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
)

var portMap = map[string]string{
	"http":  "80",
	"https": "443",
}

func MatchRegistry(reg name.Registry, in *http.Request, scheme string) bool {
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
