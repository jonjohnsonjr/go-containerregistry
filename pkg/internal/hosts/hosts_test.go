package hosts

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
)

func TestCanonicalAddressResolution(t *testing.T) {
	registry, err := name.NewRegistry("does-not-matter", name.WeakValidation)
	if err != nil {
		t.Errorf("Unexpected error during NewRegistry: %v", err)
	}

	tests := []struct {
		registry name.Registry
		scheme   string
		address  string
		want     string
	}{{
		registry: registry,
		scheme:   "http",
		address:  "registry.example.com",
		want:     "registry.example.com:80",
	}, {
		registry: registry,
		scheme:   "http",
		address:  "registry.example.com:12345",
		want:     "registry.example.com:12345",
	}, {
		registry: registry,
		scheme:   "https",
		address:  "registry.example.com",
		want:     "registry.example.com:443",
	}, {
		registry: registry,
		scheme:   "https",
		address:  "registry.example.com:12345",
		want:     "registry.example.com:12345",
	}, {
		registry: registry,
		scheme:   "http",
		address:  "registry.example.com:",
		want:     "registry.example.com:80",
	}, {
		registry: registry,
		scheme:   "https",
		address:  "registry.example.com:",
		want:     "registry.example.com:443",
	}, {
		registry: registry,
		scheme:   "http",
		address:  "2001:db8::1",
		want:     "[2001:db8::1]:80",
	}, {
		registry: registry,
		scheme:   "https",
		address:  "2001:db8::1",
		want:     "[2001:db8::1]:443",
	}, {
		registry: registry,
		scheme:   "http",
		address:  "[2001:db8::1]:12345",
		want:     "[2001:db8::1]:12345",
	}, {
		registry: registry,
		scheme:   "https",
		address:  "[2001:db8::1]:12345",
		want:     "[2001:db8::1]:12345",
	}, {
		registry: registry,
		scheme:   "http",
		address:  "[2001:db8::1]:",
		want:     "[2001:db8::1]:80",
	}, {
		registry: registry,
		scheme:   "https",
		address:  "[2001:db8::1]:",
		want:     "[2001:db8::1]:443",
	}}

	for _, tt := range tests {
		got := canonicalAddress(tt.address, tt.scheme)
		if got != tt.want {
			t.Errorf("Wrong canonical host: wanted %v got %v", tt.want, got)
		}
	}
}

func TestMatchRegistry(t *testing.T) {
	// TODO
}
