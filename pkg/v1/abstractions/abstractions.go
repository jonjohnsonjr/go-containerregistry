package abstractions

import (
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Better names for these might be ArtifactSource or ArtifactSink.

// Source represents an abstraction from which we can read artifacts.
//
// For example:
// * a tarball can contain multiple images.
// * a remote repository can act as a source, but there's no standard way to implement Descriptors()
type Source interface {
	Descriptors() []v1.Descriptor
	Image(v1.Hash) v1.Image
	Index(v1.Hash) v1.ImageIndex
	Layer(v1.Hash) v1.Layer
}

// Sink represents an abstraction to which we can write artifacts.
type Sink interface {
	Image(v1.Image) error
	Index(v1.ImageIndex) error
	Layer(v1.Layer) error
}

// Helpful concepts?

// ImageHandle represents a union of v1.Image and v1.ImageIndex.
//
// This is useful in cases where we read an image from a Source
// and don't know ahead of time what format it's in.
type ImageHandle interface {
	Descriptor() v1.Descriptor
	Image(v1.Hash) v1.Image
	Index(v1.Hash) v1.ImageIndex
}

// Describable is a set of methods that can be used to produce a v1.Descriptor.
type Describable interface {
	MediaType() (types.MediaType, error)
	Size() (int64, error)
	Digest() (v1.Hash, error)
}
