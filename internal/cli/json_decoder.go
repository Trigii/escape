package cli

import (
	"encoding/json"
	"io"
)

// newJSONDecoder is a tiny indirection over encoding/json so json_decoder
// imports stay localised to one file. Avoids a dependency injection
// scaffold for what is, for now, a single use site.
func newJSONDecoder(r io.Reader) *json.Decoder {
	return json.NewDecoder(r)
}
