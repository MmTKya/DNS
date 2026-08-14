package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// The panel sends these exact names. The server rejects unknown fields, so a
// mismatch is a save that fails rather than one that quietly does nothing —
// which is how the first version of this was caught, by a person rather than a
// test. This pins the contract from the panel's side.
func TestIntelKeyFieldNamesMatchThePanel(t *testing.T) {
	t.Parallel()

	// Copied from web/src/api.ts.
	const body = `{"abusech_key":"a","safebrowsing_key":"b","otx_key":"c"}`

	var req intelKeysRequest
	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&req); err != nil {
		t.Fatalf("the panel's field names do not match the server's: %v", err)
	}

	if req.AbuseCh == nil || *req.AbuseCh != "a" {
		t.Error("abusech_key did not arrive")
	}
	if req.SafeBrowsing == nil || *req.SafeBrowsing != "b" {
		t.Error("safebrowsing_key did not arrive")
	}
	if req.OTX == nil || *req.OTX != "c" {
		t.Error("otx_key did not arrive")
	}
}
