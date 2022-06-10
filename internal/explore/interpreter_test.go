package explore

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-containerregistry/internal/explore/lexer"
)

func TestLexer(t *testing.T) {
	b := `{"foo":[{}, {"bar":{"foo.bar":["aGVsbG8=", "world"]}}]}`
	l := lexer.Lex("test", `.foo[1].bar["foo.bar"][0] | base64 -d`)
	want := []byte("hello")

	got, err := evalBytes(l, []byte(b))
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("%s", diff)
	}
}
