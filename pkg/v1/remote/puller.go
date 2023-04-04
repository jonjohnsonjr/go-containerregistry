package remote

import (
	"context"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
)

type Puller struct {
	o *options

	// map[name.Repository]*repoReader
	readers sync.Map
}

func NewPuller(options ...Option) (*Puller, error) {
	o, err := makeOptions(options...)
	if err != nil {
		return nil, err
	}

	return &Puller{
		o: o,
	}, nil
}

func (p *Puller) reader(ctx context.Context, repo name.Repository, o *options) (*repoReader, error) {
	v, _ := p.readers.LoadOrStore(repo, &repoReader{
		repo: repo,
		o:    o,
	})
	rr := v.(*repoReader)
	return rr, rr.init(ctx)
}

func (p *Puller) Get(ctx context.Context, ref name.Reference) (*Descriptor, error) {
	r, err := p.reader(ctx, ref.Context(), p.o)
	if err != nil {
		return nil, err
	}
	return r.f.get(ctx, ref, allManifestMediaTypes)
}

// ListPage lists a single page of tags. The "next" parameter should be empty for the first page.
// For subsequent pages, "next" should be passed from the previous page's response.
func (p *Puller) ListPage(ctx context.Context, repo name.Repository, next string) (*Tags, error) {
	r, err := p.reader(ctx, repo, p.o)
	if err != nil {
		return nil, err
	}
	return r.f.listPage(ctx, next)
}

type repoReader struct {
	repo name.Repository
	o    *options
	once sync.Once

	f *fetcher
}

// this will run once per repoWriter instance
func (r *repoReader) init(ctx context.Context) error {
	return onceErr(&r.once, func() (err error) {
		f, err := makeFetcher(r.repo, r.o)
		if err != nil {
			return err
		}

		r.f = f

		return nil
	})
}
