package remote

import (
	"context"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
)

// TODO: Caching in some way?
type Puller struct {
	o *options

	// map[name.Repository]*repoReader
	readers sync.Map
}

// TODO: func New()?
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

// TODO: Implements partial.Describable
// TODO: Very similar to remote.Descriptor
// TODO: May actually be remote.Descriptor?
type todo struct {
}

func (p *Puller) Get(ctx context.Context, ref name.Reference) (*todo, error) {
	r, err := p.reader(ctx, ref.Context(), p.o)
	if err != nil {
		return nil, err
	}
	return r.get(ctx, ref)
}

type repoReader struct {
	repo name.Repository
	o    *options
	once sync.Once

	f *fetcher

	work *workers
}

// this will run once per repoWriter instance
func (r *repoReader) init(ctx context.Context) error {
	return onceErr(&r.once, func() (err error) {
		f, err := makeFetcher(r.repo, r.o)
		if err != nil {
			return err
		}

		r.f = f
		r.work = &workers{}

		return nil
	})
}

func (r *repoReader) get(ctx context.Context, ref name.Reference) (*todo, error) {
	return nil, nil
}
