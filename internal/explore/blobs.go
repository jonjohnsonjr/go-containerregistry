// Copyright 2021 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package explore

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"

	"github.com/google/go-containerregistry/internal/gzip"
)

// Pretends to implement Seek because ServeContent only cares about checking
// for the size by calling Seek(0, io.SeekEnd)
type sizeSeeker struct {
	rc     io.Reader
	size   int64
	debug  string
	buf    *bufio.Reader
	seeked bool
}

func (s *sizeSeeker) Seek(offset int64, whence int) (int64, error) {
	if debug {
		log.Printf("sizeSeeker.Seek(%d, %d)", offset, whence)
	}
	s.seeked = true
	if offset == 0 && whence == io.SeekEnd {
		return s.size, nil
	}
	if offset == 0 && whence == io.SeekStart {
		return 0, nil
	}

	return 0, fmt.Errorf("ServeContent(%q): Seek(%d, %d)", s.debug, offset, whence)
}

func (s *sizeSeeker) Read(p []byte) (int, error) {
	if debug {
		log.Printf("sizeSeeker.Read(%d)", len(p))
	}
	// Handle first read.
	if s.buf == nil {
		if debug {
			log.Println("first read")
		}
		if len(p) <= bufferLen {
			s.buf = bufio.NewReaderSize(s.rc, bufferLen)
		} else {
			s.buf = bufio.NewReaderSize(s.rc, len(p))
		}

		// Currently, http will sniff before it seeks for size. If we haven't seen
		// a Read() but have seen a Seek already, that means we shouldn't peek.
		if !s.seeked {
			// Peek to handle the first content sniff.
			b, err := s.buf.Peek(len(p))
			if err != nil {
				if err == io.EOF {
					n, _ := bytes.NewReader(b).Read(p)
					return n, io.EOF
				} else {
					return 0, err
				}
			}
			return bytes.NewReader(b).Read(p)
		}
	}

	// TODO: We assume they will always sniff then reset.
	n, err := s.buf.Read(p)
	if debug {
		log.Printf("sizeSeeker.Read(%d): (%d, %v)", len(p), n, err)
	}
	return n, err
}

type sizeBlob struct {
	io.ReadCloser
	size int64
}

func (s *sizeBlob) Size() (int64, error) {
	if debug {
		log.Printf("sizeBlob.Size()")
	}
	return s.size, nil
}

const (
	magicGNU, versionGNU     = "ustar ", " \x00"
	magicUSTAR, versionUSTAR = "ustar\x00", "00"
)

func tarPeek(r io.Reader) (bool, gzip.PeekReader, error) {
	// Make sure it's more than 512
	pr := bufio.NewReaderSize(r, 1024)

	block, err := pr.Peek(512)
	if err != nil {
		// https://github.com/google/go-containerregistry/issues/367
		if err == io.EOF {
			return false, pr, nil
		}
		return false, pr, err
	}

	magic := string(block[257:][:6])
	isTar := magic == magicGNU || magic == magicUSTAR
	return isTar, pr, nil
}
