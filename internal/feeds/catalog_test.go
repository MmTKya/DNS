package feeds

import "testing"

func TestAFeedThatIsSlowToFillSaysSo(t *testing.T) {
	// Switching on a paged API and switching on a broken feed look identical
	// from the panel: nothing happens. The difference is half an hour, and the
	// only thing that separates them for the person watching is being told.
	for _, entry := range Catalog() {
		if entry.Connector && entry.FirstFill == "" {
			t.Errorf("%s is filled through an API but does not say how long that takes", entry.ID)
		}
	}
}
