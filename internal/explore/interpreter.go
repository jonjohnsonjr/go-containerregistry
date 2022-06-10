package explore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/internal/explore/lexer"
)

func evalBytes(output *simpleOutputter, l *lexer.Lexer, b []byte) ([]byte, error) {
	raw := json.RawMessage(b)

	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	for {
		item := l.NextItem()
		if item.Typ == lexer.ItemEOF {
			break
		}
		switch item.Typ {
		case lexer.ItemError:
			return nil, fmt.Errorf("lexer.ItemError: %w", item.Val)
		case lexer.ItemAccessor:
			vv, ok := v.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("eval: access %s", item.Val)
			}
			v = vv[item.Val]
		case lexer.ItemIndex:
			vv, ok := v.([]interface{})
			if !ok {
				return nil, fmt.Errorf("eval: index %s", item.Val)
			}
			idx, err := strconv.Atoi(item.Val)
			if err != nil {
				return nil, fmt.Errorf("atoi: %w", err)
			}
			v = vv[idx]
		case lexer.ItemSentinel:
			switch strings.TrimSpace(item.Val) {
			case "base64 -d":
				s, err := toString(v)
				if err != nil {
					return nil, err
				}

				v, err = base64.StdEncoding.DecodeString(s)
				if err != nil {
					return nil, fmt.Errorf("base64 -d: %w", err)
				}
			case "raw":
				b, err := toBytes(v)
				if err != nil {
					return nil, err
				}
				if _, err := output.w.Write(b); err != nil {
					return nil, err
				}
			case "jq":
				b, err := toBytes(v)
				if err != nil {
					return nil, err
				}
				if err := renderJSON(output, b); err != nil {
					return nil, err
				}
			}
		}
	}

	b, err := toBytes(v)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func toString(v interface{}) (string, error) {
	switch vv := v.(type) {
	case string:
		return vv, nil
	case []byte:
		return string(vv), nil
	}
	return "", fmt.Errorf("cannot convert %T to string", v)
}

func toBytes(v interface{}) ([]byte, error) {
	switch vv := v.(type) {
	case string:
		return []byte(vv), nil
	case []byte:
		return vv, nil
	}
	return nil, fmt.Errorf("cannot convert %T to bytes", v)
}
