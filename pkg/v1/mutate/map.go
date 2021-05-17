package mutate

import (
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
)

type Mapper struct {
	Image       func(v1.Image) (v1.Image, error)
	Index       func(v1.ImageIndex) (v1.ImageIndex, error)
	Layer       func(v1.Layer) (v1.Layer, error)
	Describable func(partial.Describable) (partial.Describable, error)
}

func (m *Mapper) Func(d partial.Describable) (partial.Describable, error) {
	switch t := d.(type) {
	case v1.ImageIndex:
		return m.Index(t)
	case v1.Image:
		return m.Image(t)
	case v1.Layer:
		return m.Layer(t)
	default:
		return m.Describable(t)
	}
}

type MapFunc = func(partial.Describable) (partial.Describable, error)

// TODO: Append to empty.Whatever
func Map(d partial.Describable, f MapFunc) (partial.Describable, error) {
	switch t := d.(type) {
	case v1.ImageIndex:
	case v1.Image:
	case v1.Layer:
	default:
		return f(t)
	}
	return f(d)
}
