package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/tmc/dot"
)

func main() {
	input := "ubuntu"
	if len(os.Args) > 1 {
		input = os.Args[1]
	}

	repo, err := name.NewRepository(input)
	if err != nil {
		log.Fatal(err)
	}

	g, err := build(repo)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf(g.String())
}

func build(repo name.Repository) (*Graph, error) {
	g := New(repo.String())
	tags, err := remote.List(repo, authn.Anonymous, http.DefaultTransport)
	if err != nil {
		return nil, err
	}

	for _, t := range tags {
		tag, err := name.NewTag(fmt.Sprintf("%s:%s", repo, t))
		if err != nil {
			return nil, err
		}
		desc, err := remote.Get(tag)
		if err != nil {
			return nil, err
		}
		ref, err := name.NewDigest(fmt.Sprintf("%s@%s", repo, desc.Digest))
		if err != nil {
			return nil, err
		}

		switch desc.MediaType {
		case types.OCIImageIndex, types.DockerManifestList:
			idx, err := desc.ImageIndex()
			if err != nil {
				return nil, err
			}
			m, err := idx.IndexManifest()
			if err != nil {
				return nil, err
			}
			for _, manifest := range m.Manifests {
				// TODO: recurse?
				img, err := idx.Image(manifest.Digest)
				if err != nil {
					return nil, err
				}
				g.AddManifest(ref.Identifier(), manifest.Digest.String())
				if err := g.AddBlobs(manifest.Digest.String(), img); err != nil {
					return nil, err
				}
			}
			g.TagIndex(tag.Identifier(), ref.Identifier())
		case types.OCIManifestSchema1, types.DockerManifestSchema2:
			img, err := desc.Image()
			if err != nil {
				return nil, err
			}
			if err := g.AddBlobs(ref.Identifier(), img); err != nil {
				return nil, err
			}
			g.TagImage(tag.Identifier(), ref.Identifier())
		case types.DockerManifestSchema1, types.DockerManifestSchema1Signed:
			m := schema1{}
			if err := json.Unmarshal(desc.Manifest, &m); err != nil {
				return nil, err
			}
			for _, blob := range m.FSLayers {
				g.AddBlob(ref.Identifier(), blob.BlobSum.String())
			}
			g.TagImage(tag.Identifier(), ref.Identifier())
		}
	}

	return g, nil
}

type Graph struct {
	*dot.Graph

	tags      map[string]*dot.Node
	manifests map[string]*dot.Node
	blobs     map[string]*dot.Node

	tg *dot.SubGraph
	mg *dot.SubGraph
	bg *dot.SubGraph
}

func New(repo string) *Graph {
	g := dot.NewGraph("G")
	_ = g.Set("shape", "box")
	_ = g.Set("label", "Images in "+repo)
	_ = g.Set("rankdir", "LR")

	graph := &Graph{
		Graph:     g,
		tags:      make(map[string]*dot.Node),
		indexes:   make(map[string]*dot.Node),
		manifests: make(map[string]*dot.Node),
		blobs:     make(map[string]*dot.Node),
		tg:        dot.NewSubgraph("tags"),
		ig:        dot.NewSubgraph("indexes"),
		mg:        dot.NewSubgraph("manifests"),
		bg:        dot.NewSubgraph("blobs"),
	}

	for _, sg := range []*dot.SubGraph{graph.tg, graph.mg, graph.bg} {
		graph.AddSubgraph(sg)
	}

	return graph
}

func escape(s string) string {
	return strings.ReplaceAll(s, ":", "\\:")
}

func (g *Graph) TagImage(src, dst string) {
	t := dot.NewNode(escape(src))
	g.tags[src] = t
	g.tg.AddNode(t)

	m, ok := g.manifests[dst]
	if !ok {
		m = dot.NewNode(escape(dst))
		m.Set("shape", "box")
		g.manifests[dst] = m
		g.mg.AddNode(m)
	}

	g.AddEdge(dot.NewEdge(t, m))
}

func (g *Graph) TagIndex(src, dst string) {
	t := dot.NewNode(escape(src))
	g.tags[src] = t
	g.tg.AddNode(t)

	m, ok := g.indexes[dst]
	if !ok {
		m = dot.NewNode(escape(dst))
		m.Set("shape", "box")
		g.indexes[dst] = m
		g.ig.AddNode(m)
	}

	g.AddEdge(dot.NewEdge(t, m))
}

func (g *Graph) AddManifest(src, dst string) {
	i := dot.NewNode(escape(src))
	g.indexes[src] = i
	g.ig.AddNode(i)

	m, ok := g.manifests[dst]
	if !ok {
		m = dot.NewNode(escape(dst))
		m.Set("shape", "box")
		g.manifests[dst] = m
		g.mg.AddNode(m)
	}

	g.AddEdge(dot.NewEdge(i, m))
}

func (g *Graph) AddBlobs(src string, img v1.Image) error {
	m, err := img.Manifest()
	if err != nil {
		return err
	}
	for _, layer := range m.Layers {
		g.AddBlob(src, layer.Digest.String())
	}
	g.AddConfig(src, m.Config.Digest.String())
	return nil
}

func (g *Graph) AddBlob(src, blob string) {
	m, ok := g.manifests[src]
	if !ok {
		m = dot.NewNode(escape(src))
		m.Set("shape", "box")
		g.manifests[src] = m
		g.mg.AddNode(m)
	}

	b, ok := g.blobs[blob]
	if !ok {
		b = dot.NewNode(escape(blob))
		g.blobs[blob] = b
		g.bg.AddNode(b)
	}

	g.AddEdge(dot.NewEdge(m, b))
}

func (g *Graph) AddConfig(src, blob string) {
	m, ok := g.manifests[src]
	if !ok {
		m = dot.NewNode(escape(src))
		m.Set("shape", "box")
		g.manifests[src] = m
		g.mg.AddNode(m)
	}

	b, ok := g.blobs[blob]
	if !ok {
		b = dot.NewNode(escape(blob))
		g.blobs[blob] = b
		g.bg.AddNode(b)
	}

	e := dot.NewEdge(m, b)
	e.Set("style", "dashed")

	g.AddEdge(e)
}

type schema1 struct {
	FSLayers []struct {
		BlobSum v1.Hash `json:"blobSum"`
	} `json:"fsLayers"`
}
