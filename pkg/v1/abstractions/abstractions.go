package abstractions

import (
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Better names for these might be ArtifactSource or ArtifactSink.

// Source represents an abstraction from which we can read artifacts.
//
// Descriptors() and Tags() are useful for discovering what's available from a Source.
// Image(), Index(), and Layer() are useful for actually fetching content from that Source.
//
// For example:
// * a tarball can contain multiple images, exposing its contents via Tags.
// * a remote repository can act as a source, exposing its contents via Tags (/tags/list).
// * any image index can act as a source, exposing its children via Descriptors.
// * an OCI image layout acts as a source, exposing contents of index.json via Descriptors.
type Source interface {
	Descriptors() []v1.Descriptor
	Tags() []name.Tag

	Image(v1.Hash) v1.Image
	Index(v1.Hash) v1.ImageIndex
	Layer(v1.Hash) v1.Layer

	// This could be a name.Tag or a v1.Hash or a name.Digest but golang doesn't have method overloading :(
	// Not sure best way to handle it.
	//
	// Perhaps "ImagePointer" or something would be the union of (name.Tag + name.Digest + v1.Hash).
	//
	// name.Reference is almost correct, but sometimes we have a v1.Hash without a repo.
	// We could use them for sentinel repos?
	//
	// The Source probably knows if the string is supposed to be a v1.Hash or a name.Reference...
	ImageDescriptor(string) ImageDescriptor
}

// Sink represents an abstraction to which we can write artifacts.
type Sink interface {
	Image(v1.Image) error
	Index(v1.ImageIndex) error
	Layer(v1.Layer) error
}

// Useful ideas?

// ImageDescriptor represents a union of v1.Image and v1.ImageIndex.
//
// This is useful in cases where we read an image from a Source
// and don't know ahead of time what format it's in.
type ImageDescriptor interface {
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
