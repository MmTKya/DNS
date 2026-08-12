package filter

import (
	"sync/atomic"
	"time"
)

// Engine holds the ruleset the datapath consults, and lets it be replaced
// while queries are in flight.
//
// Compiling a new index takes seconds for a large list; blocking resolution
// for that long would be an outage.  So a new index is built off to the side
// and swapped in with a single atomic store: queries in progress finish
// against the old one, and the next query sees the new one.
type Engine struct {
	index atomic.Pointer[Index]

	// compiledAt is the wall-clock time of the last successful swap, reported
	// by the panel.
	compiledAt atomic.Int64
}

// NewEngine returns an engine with an empty ruleset, which matches nothing.
func NewEngine() *Engine {
	e := &Engine{}
	e.Replace(NewBuilder().Build())

	return e
}

// Replace swaps in a newly compiled index.
func (e *Engine) Replace(idx *Index) {
	e.index.Store(idx)
	e.compiledAt.Store(time.Now().Unix())
}

// Index returns the current ruleset.
func (e *Engine) Index() *Index { return e.index.Load() }

// CompiledAt reports when the current ruleset was installed.
func (e *Engine) CompiledAt() time.Time {
	sec := e.compiledAt.Load()
	if sec == 0 {
		return time.Time{}
	}

	return time.Unix(sec, 0)
}

// Match tests a query against the current ruleset.
func (e *Engine) Match(host string, qtype uint16, clientID string) Result {
	return e.index.Load().Match(host, qtype, clientID)
}

// Stats summarises the loaded ruleset for the panel.
type Stats struct {
	Rules       int          `json:"rules"`
	Sources     []SourceInfo `json:"sources"`
	ApproxBytes int          `json:"approx_bytes"`
	CompiledAt  time.Time    `json:"compiled_at"`
}

// Stats returns a snapshot of the current ruleset.
func (e *Engine) Stats() Stats {
	idx := e.index.Load()

	return Stats{
		Rules:       idx.Len(),
		Sources:     idx.Sources(),
		ApproxBytes: idx.ApproxBytes(),
		CompiledAt:  e.CompiledAt(),
	}
}
