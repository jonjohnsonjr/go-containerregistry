package transport

import (
	"net/http"
	"os"

	"github.com/google/go-containerregistry/pkg/logs"
)

func init() {
	logs.Debug.SetOutput(os.Stderr)
}

type logTransport struct {
	inner http.RoundTripper
}

// NewRetry returns a transport that logs requests and responses to
// github.com/google/go-containerregistry/pkg/logs.Debug.
func NewLogger(inner http.RoundTripper) http.RoundTripper {
	return &logTransport{inner}
}

func (t *logTransport) RoundTrip(in *http.Request) (out *http.Response, err error) {
	// Inspired by: github.com/motemen/go-loghttp
	logs.Debug.Printf("--> %s %s", in.Method, in.URL)
	out, err = t.inner.RoundTrip(in)
	if err != nil {
		logs.Debug.Printf("<-- %v %s", err, in.URL)
	}
	if out != nil {
		logs.Debug.Printf("<-- %d %s", out.StatusCode, out.Request.URL)
	}
	return
}
