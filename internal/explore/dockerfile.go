package explore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/dustin/go-humanize"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type Schema1History struct {
	V1Compatibility string `json:"v1Compatibility"`
}

type Schema1 struct {
	History []Schema1History `json:"history"`
}

type Config struct {
	Cmd []string `json:"Cmd"`
}

type Compat struct {
	ContainerConfig Config `json:"container_config"`
}

// TODO: Dedupe
func renderDockerfileSchema1(w io.Writer, b []byte) error {
	m := Schema1{}
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	args := []string{}
	for i := len(m.History) - 1; i >= 0; i-- {
		compat := m.History[i]
		var sb strings.Builder
		c := Compat{}
		if err := json.Unmarshal([]byte(compat.V1Compatibility), &c); err != nil {
			return err
		}

		cb := strings.Join(c.ContainerConfig.Cmd, " ")

		// Attempt to handle weird ARG stuff.
		maybe := strings.TrimSpace(strings.TrimPrefix(cb, "/bin/sh -c #(nop)"))
		if before, after, ok := strings.Cut(maybe, "ARG "); ok && before == "" {
			args = append(args, after)
		} else if strings.HasPrefix(cb, "|") {
			if _, cb, ok = strings.Cut(cb, " "); ok {
				for _, arg := range args {
					cb = strings.TrimSpace(strings.TrimPrefix(cb, arg))
				}

				// Hack around array syntax.
				if !strings.HasPrefix(cb, "/bin/sh -c ") {
					cb = "/bin/sh -c " + cb
				}
			}
		}
		if err := renderCreatedBy(&sb, []byte(cb)); err != nil {
			return err
		}
		if _, err := sb.Write([]byte("\n\n")); err != nil {
			return err
		}
		if _, err := w.Write([]byte(sb.String())); err != nil {
			return err
		}
	}
	return nil
}

func renderDockerfile(w io.Writer, b []byte, m *v1.Manifest) error {
	cf, err := v1.ParseConfigFile(bytes.NewReader(b))
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "<table>\n")
	args := []string{}
	index := -1
	for _, hist := range cf.History {
		digest := ""
		size := int64(0)
		if m != nil {
			if !hist.EmptyLayer {
				index++
				if index < len(m.Layers) {
					digest = m.Layers[index].Digest.String()
					if _, after, ok := strings.Cut(digest, ":"); ok {
						if len(after) > 8 {
							digest = after[:8]
						}
					}
					size = m.Layers[index].Size
				}
			}
		}
		fmt.Fprintf(w, "<tr>\n")
		fmt.Fprintf(w, "<td class=\"noselect\"><p><em>%s</em></p></td>\n", digest)
		if size != 0 {
			human := humanize.Bytes(uint64(size))
			fmt.Fprintf(w, "<td class=\"noselect\"><p title=\"%d bytes\">%s</p></td>\n", size, human)
		} else {
			fmt.Fprintf(w, "<td></td>\n")
		}

		var sb strings.Builder
		cb := hist.CreatedBy
		fmt.Fprintf(w, "<td>\n<pre>\n")

		// Attempt to handle weird ARG stuff.
		maybe := strings.TrimSpace(strings.TrimPrefix(cb, "/bin/sh -c #(nop)"))
		if before, after, ok := strings.Cut(maybe, "ARG "); ok && before == "" {
			args = append(args, after)
		} else if strings.HasPrefix(cb, "|") {
			if _, cb, ok = strings.Cut(cb, " "); ok {
				for _, arg := range args {
					cb = strings.TrimSpace(strings.TrimPrefix(cb, arg))
				}

				// Hack around array syntax.
				if !strings.HasPrefix(cb, "/bin/sh -c ") {
					cb = "/bin/sh -c " + cb
				}
			}
		}
		if err := renderCreatedBy(&sb, []byte(cb)); err != nil {
			return err
		}
		if _, err := sb.Write([]byte("\n\n")); err != nil {
			return err
		}
		if _, err := w.Write([]byte(sb.String())); err != nil {
			return err
		}
		fmt.Fprintf(w, "</pre>\n</td>\n")
		fmt.Fprintf(w, "</tr>\n")
	}
	fmt.Fprintf(w, "</table>\n")
	return nil
}

const (
	winPrefix = `powershell -Command $ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';`
	linPrefix = `/bin/sh -c`
)

func renderCreatedBy(w io.Writer, b []byte) error {
	// Heuristically try to format this correctly.
	for _, prefix := range []string{linPrefix, winPrefix} {
		b = bytes.TrimPrefix(b, []byte(prefix+" #(nop)"))
		if bytes.HasPrefix(b, []byte(prefix)) {
			b = bytes.Replace(b, []byte(prefix), []byte("RUN"), 1)
		}
	}
	b = bytes.ReplaceAll(b, []byte(" \t"), []byte(" \\\n\t"))
	b = bytes.ReplaceAll(b, []byte("&&\t"), []byte("\\\n&&\t"))
	b = whitespaceRegex.ReplaceAllFunc(b, whitespaceRepl)
	b = bytes.TrimSpace(b)
	if bytes.HasPrefix(b, []byte("EXPOSE")) {
		// Turn the map version into the dockerfile version
		b = bytes.TrimSuffix(b, []byte("]"))
		b = bytes.Replace(b, []byte("map["), []byte(""), 1)
		b = bytes.ReplaceAll(b, []byte(":{}"), []byte(""))
	}
	if bytes.HasPrefix(b, []byte("|")) {
		if _, after, ok := bytes.Cut(b, []byte("/bin/sh -c")); ok {
			b = []byte("RUN")
			b = append(b, after...)
		}
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	return nil
}
