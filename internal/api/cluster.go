package api

import (
	"bytes"
	"fmt"
	"net/http"
	"time"

	"github.com/MmTKya/DNS/internal/backup"
)

// handleClusterState is what a peer polls.  It carries no secrets: a node's
// role, revision and health are the minimum needed to decide whether to
// replicate, and nothing more.
func (s *Server) handleClusterState(w http.ResponseWriter, r *http.Request) {
	if s.deps.Cluster == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "clustering is not configured")

		return
	}

	if !s.deps.Cluster.Authenticate(r.Header.Get("X-SedDNS-Signature"), nil) {
		s.writeError(w, r, http.StatusUnauthorized, "peer authentication failed")

		return
	}

	s.writeJSON(w, r, http.StatusOK, s.deps.Cluster.Status(r.Context()).Self)
}

// handleClusterSnapshot serves the configuration a replica applies.
//
// The body is signed with the shared token: a replica that applied whatever
// arrived on this port could be handed a configuration with filtering switched
// off by anyone who could reach it.
func (s *Server) handleClusterSnapshot(w http.ResponseWriter, r *http.Request) {
	if s.deps.Cluster == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "clustering is not configured")

		return
	}

	if !s.deps.Cluster.Authenticate(r.Header.Get("X-SedDNS-Signature"), nil) {
		s.writeError(w, r, http.StatusUnauthorized, "peer authentication failed")

		return
	}

	archive, manifest, err := s.deps.Cluster.SnapshotArchive(r.Context(), s.deps.ConfigPath)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("X-SedDNS-Signature", s.deps.Cluster.SignSnapshot(archive))
	w.Header().Set("X-SedDNS-Revision", fmt.Sprint(manifest.Revision))
	w.WriteHeader(http.StatusOK)

	if _, err = w.Write(archive); err != nil {
		s.deps.Logger.ErrorContext(r.Context(), "sending snapshot to a peer", "err", err)
	}
}

// handleClusterStatus is the panel's view of the cluster.
func (s *Server) handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	if s.deps.Cluster == nil {
		s.writeJSON(w, r, http.StatusOK, map[string]any{"enabled": false})

		return
	}

	s.writeJSON(w, r, http.StatusOK, s.deps.Cluster.Status(r.Context()))
}

// handleClusterDemote returns a promoted replica to its normal role, which is
// what an operator does once the original primary is back.
func (s *Server) handleClusterDemote(w http.ResponseWriter, r *http.Request) {
	if s.deps.Cluster == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "clustering is not configured")

		return
	}

	if err := s.deps.Cluster.Demote(r.Context()); err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleBackupExport downloads a full backup.
func (s *Server) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	// Secrets are included only when asked for, and the filename says which
	// kind of file this is, because one of them is as sensitive as the node.
	includeSecrets := r.URL.Query().Get("secrets") == "true"

	name := fmt.Sprintf("seddns-backup-%s.tar.gz", time.Now().UTC().Format("20060102-150405"))
	if includeSecrets {
		name = fmt.Sprintf("seddns-backup-with-secrets-%s.tar.gz", time.Now().UTC().Format("20060102-150405"))
	}

	var buf bytes.Buffer
	manifest, err := backup.Export(r.Context(), s.deps.Store, &buf, backup.Options{
		IncludeSecrets: includeSecrets,
		ConfigPath:     s.deps.ConfigPath,
		Version:        s.deps.Version,
	})
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("X-SedDNS-Backup-Hash", manifest.Hash)
	w.WriteHeader(http.StatusOK)

	if _, err = w.Write(buf.Bytes()); err != nil {
		s.deps.Logger.ErrorContext(r.Context(), "sending backup", "err", err)
	}
}

// maxUploadBytes bounds a restore upload.
const maxUploadBytes = 256 << 20

// handleBackupImport restores a backup.
func (s *Server) handleBackupImport(w http.ResponseWriter, r *http.Request) {
	dryRun := r.URL.Query().Get("dry_run") == "true"

	body := http.MaxBytesReader(w, r.Body, maxUploadBytes)
	defer func() { _ = body.Close() }()

	manifest, err := backup.Import(r.Context(), s.deps.Store, body, backup.ImportOptions{
		// The configuration file is deliberately not overwritten from the
		// panel: an archive from another node carries its listeners, and
		// restoring those could leave this node unreachable.
		DryRun: dryRun,
	})
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, err.Error())

		return
	}

	if !dryRun {
		// Feeds, rules and clients all changed underneath the running node.
		s.recompileInBackground()
	}

	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"manifest": manifest,
		"dry_run":  dryRun,
		"note":     "the configuration file was not replaced; only stored settings and rules were restored",
	})
}
