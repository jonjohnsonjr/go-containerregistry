# `stream`

[![GoDoc](https://godoc.org/github.com/google/go-containerregistry/pkg/v1/stream?status.svg)](https://godoc.org/github.com/google/go-containerregistry/pkg/v1/stream)

## Usage

```go
package main

import (
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/stream"
)

// upload the contents of stdin as a layer to a local registry
func main() {
	repo, err := name.NewRepository("localhost:5000/stream")
	if err != nil {
		panic(err)
	}

	layer := stream.NewLayer(os.Stdin)

	if err := remote.WriteLayer(repo, layer); err != nil {
		panic(err)
	}
}
```

## Structure

<p align="center">
  <img src="/images/stream.dot.svg" />
</p>
