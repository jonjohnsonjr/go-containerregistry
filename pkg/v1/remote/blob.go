package remote

import (
	"io"

	"github.com/google/go-containerregistry/pkg/internal/redact"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func Blob(ref name.Reference, options ...Option) (io.ReadCloser, error) {
	o, err := makeOptions(ref.Context(), options...)
	if err != nil {
		return nil, err
	}

	f, err := makeFetcher(ref, o)
	if err != nil {
		return nil, err
	}

	h, err := v1.NewHash(ref.Identifier())
	if err != nil {
		return nil, err
	}

	ctx := redact.NewContext(o.context, "omitting binary blobs from logs")
	return f.fetchBlob(ctx, h)
}
