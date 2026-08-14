package api

import (
	"net/http"

	"github.com/MmTKya/DNS/internal/hostinfo"
)

// handleHostInfo reports the health of the machine itself.
//
// Under System rather than on the dashboard: this is the screen someone opens
// when something is wrong, and a household should not have to learn what a
// load average is to use the product day to day. But when the node does go
// slow, the cause is as often the machine — a full card, a hot processor, a
// power supply that sags — as it is the network, and without this the only way
// to tell them apart is a terminal.
func (s *Server) handleHostInfo(w http.ResponseWriter, r *http.Request) {
	if s.deps.Host == nil {
		s.writeJSON(w, r, http.StatusOK, hostinfo.Snapshot{})

		return
	}

	s.writeJSON(w, r, http.StatusOK, s.deps.Host.Read())
}
