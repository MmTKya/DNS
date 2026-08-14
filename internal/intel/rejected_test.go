package intel

import (
	"errors"
	"fmt"
	"testing"
)

// A rejected key looks exactly like a source that found nothing, and that is
// the whole problem: the queue keeps running, keeps finding nothing, and
// nobody learns their key was wrong. It has to be distinguishable.
func TestRejectedKeyIsDistinguishable(t *testing.T) {
	t.Parallel()

	rejected := fmt.Errorf("threatfox-api.abuse.ch: %w", ErrKeyRejected)
	down := errors.New("threatfox-api.abuse.ch returned 503 Service Unavailable")

	if !errors.Is(rejected, ErrKeyRejected) {
		t.Error("a rejected key did not match ErrKeyRejected")
	}
	if errors.Is(down, ErrKeyRejected) {
		t.Error("a source being down was reported as a rejected key; one needs a person, the other fixes itself")
	}
}

// The panel shows which source refused, so the name has to survive wrapping.
func TestSourceOfNamesTheEndpoint(t *testing.T) {
	t.Parallel()

	err := fmt.Errorf("threatfox-api.abuse.ch: %w", ErrKeyRejected)
	if got := sourceOf(err); got != "threatfox-api.abuse.ch" {
		t.Errorf("sourceOf() = %q, want the endpoint", got)
	}

	if got := sourceOf(errors.New("something with no colon")); got == "" {
		t.Error("sourceOf() returned nothing for an unstructured error")
	}
}
