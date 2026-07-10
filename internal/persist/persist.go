// Package persist attributes an egressing process to what installed and
// launched it: a launchd job, a cron entry, a shell-rc hook, or a plain
// interactive session. Attribution is read-only observation; it never gates
// or denies a connection.
//
// v1 coverage is macOS launchd, cron, and shell-rc hooks via the process's
// ancestor chain. Not yet attributed: classic Login Items, one-shot at jobs,
// package-manager postinstall processes without a launchd/cron/rc artifact,
// and non-darwin platforms.
package persist

import (
	"fmt"
	"time"

	"github.com/byliu-labs/egress-guard/internal/procid"
)

// SourceKind is the persistence mechanism a process was attributed to.
type SourceKind string

const (
	KindLaunchd SourceKind = "launchd"
	KindCron    SourceKind = "cron"
	KindRCHook  SourceKind = "rc_hook"
	KindSession SourceKind = "session"
	KindUnknown SourceKind = "unknown"
)

// Source is the attribution result for one egressing process.
type Source struct {
	Kind      SourceKind `json:"kind"`
	Label     string     `json:"label,omitempty"`
	FirstSeen time.Time  `json:"first_seen"`
	New       bool       `json:"new,omitempty"`
}

func isPersistentKind(k SourceKind) bool {
	return k == KindLaunchd || k == KindCron || k == KindRCHook
}

// Attribute maps an egressing process to its best-effort persistence source.
func Attribute(pi procid.ProcInfo) (Source, error) {
	kind, label, err := classify(pi)
	if err != nil {
		return Source{Kind: KindUnknown}, fmt.Errorf("persist: attribute pid %d: %w", pi.PID, err)
	}
	if !isPersistentKind(kind) {
		return Source{Kind: kind, Label: label}, nil
	}
	firstSeen, isNew, err := recordFirstSeen(kind, label)
	if err != nil {
		return Source{Kind: kind, Label: label}, fmt.Errorf("persist: first-seen tracking pid %d: %w", pi.PID, err)
	}
	return Source{Kind: kind, Label: label, FirstSeen: firstSeen, New: isNew}, nil
}
