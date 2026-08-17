package daemon

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/byliu-labs/egress-guard/internal/allowlist"
	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/drift"
	"github.com/byliu-labs/egress-guard/internal/explain"
	"github.com/byliu-labs/egress-guard/internal/pending"
	"github.com/byliu-labs/egress-guard/internal/persist"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/prompt"
	"github.com/byliu-labs/egress-guard/internal/signature"
	"github.com/byliu-labs/egress-guard/internal/tlsparse"
)

// decisionOutcome is the verdict from decideBranch (post-SNI). The exempt
// fast-path in handle() never reaches decideBranch — but decideBranch still
// re-checks Exempt for correctness and to keep the branch tests honest.
type decisionOutcome int

const (
	outcomeAllow decisionOutcome = iota
	outcomeDeny
	outcomeExempt
)

// explainTimeout bounds the advisory explainer call so a slow or hung BYO
// endpoint can never delay the user's prompt from rendering. Its own HTTP
// client has a 15s timeout — too long to hold a prompt — so the daemon caps it
// here. A var (not const) so tests can shrink it.
var explainTimeout = 3 * time.Second

const maxGraceHashesPerPath = 16

// entryFor builds a decisionlog.Entry pre-populated with process, signature,
// and trust-tier context. The caller adds DestIP/DestPort because those come
// from the Kernel lookup, not from procid.
func entryFor(decision decisionlog.Decision, reason, host string, pi procid.ProcInfo, sig signature.SignedIdentity, tier decisionlog.TrustTier) decisionlog.Entry {
	entry := entryForWithoutPersistence(decision, reason, host, pi, sig, tier)
	entry.Persistence = attributePersistence(pi)
	return entry
}

func entryForWithoutPersistence(decision decisionlog.Decision, reason, host string, pi procid.ProcInfo, sig signature.SignedIdentity, tier decisionlog.TrustTier) decisionlog.Entry {
	return entryForWithoutPersistenceWithHash(decision, reason, host, pi, sig, tier, true)
}

func entryForWithoutPersistenceNoHash(decision decisionlog.Decision, reason, host string, pi procid.ProcInfo, sig signature.SignedIdentity, tier decisionlog.TrustTier) decisionlog.Entry {
	return entryForWithoutPersistenceWithHash(decision, reason, host, pi, sig, tier, false)
}

func entryForWithoutPersistenceWithHash(decision decisionlog.Decision, reason, host string, pi procid.ProcInfo, sig signature.SignedIdentity, tier decisionlog.TrustTier, includeHash bool) decisionlog.Entry {
	entry := decisionlog.Entry{
		Decision:  decision,
		Action:    string(decision),
		Reason:    reason,
		TrustTier: tier,
		ConnID:    newConnID(),
		Host:      host,
		PID:       pi.PID,
		PPID:      pi.PPID,
		Exe:       pi.Exe,
		Comm:      pi.Comm,
		Argv:      pi.Argv,
		Cwd:       pi.Cwd,
		PName:     pi.PComm,
		TeamID:    sig.TeamID,
		SigValid:  sig.Valid,
	}
	if includeHash {
		entry.ExeSHA256 = exeSHA256(pi.Exe)
	}
	return entry
}

// writeFlow records how a connection actually behaved, once it has closed. It
// reuses the decision record's identity and destination so the pair can be
// scored without a join, and carries only counts and elapsed time — never
// payload. PHILOSOPHY.md §4.8.
func (d *Daemon) writeFlow(connID string, entry decisionlog.Entry, up, down int64, started time.Time) {
	if connID == "" {
		return
	}
	flow := decisionlog.Entry{
		Timestamp:  timeNow().UTC().Format(time.RFC3339),
		Kind:       decisionlog.KindFlow,
		ConnID:     connID,
		Decision:   entry.Decision,
		Action:     entry.Action,
		Host:       entry.Host,
		DestIP:     entry.DestIP,
		DestPort:   entry.DestPort,
		PID:        entry.PID,
		Exe:        entry.Exe,
		Comm:       entry.Comm,
		ExeSHA256:  entry.ExeSHA256,
		TeamID:     entry.TeamID,
		BytesUp:    up,
		BytesDown:  down,
		DurationMS: timeNow().Sub(started).Milliseconds(),
	}
	_ = d.opts.Log.Write(flow)
}

type persistenceKey struct {
	pid  int
	ppid int
	exe  string
}

var (
	persistenceMu        sync.Mutex
	persistenceCache     = map[persistenceKey]*persist.Source{}
	persistenceAttribute = persist.Attribute
)

func attributePersistence(pi procid.ProcInfo) *persist.Source {
	if pi.PID == 0 {
		return nil
	}
	key := persistenceKey{pid: pi.PID, ppid: pi.PPID, exe: pi.Exe}
	persistenceMu.Lock()
	if cached, ok := persistenceCache[key]; ok {
		persistenceMu.Unlock()
		return cached
	}
	persistenceMu.Unlock()

	src, err := persistenceAttribute(pi)
	var out *persist.Source
	if err != nil {
		out = nil
	} else {
		out = &src
	}

	persistenceMu.Lock()
	persistenceCache[key] = out
	persistenceMu.Unlock()
	return out
}

// decideBranch is the in-package decision logic, separated from the I/O of
// reading bytes off the wire. handle() composes this with reads/writes.
//
// Exempt is also checked here (in addition to handle()'s fast-path) so the
// branch tests can exercise it without needing a live socket and so the logic
// is robust if the fast-path ever gets refactored.
func (d *Daemon) decideBranch(host string, dstIP net.IP, pi procid.ProcInfo, sig signature.SignedIdentity) (decisionOutcome, decisionlog.Entry) {
	return d.decideBranchWithIdentity(host, dstIP, pi, sig, d.identityFor(pi, sig))
}

func (d *Daemon) decideBranchWithIdentity(host string, dstIP net.IP, pi procid.ProcInfo, sig signature.SignedIdentity, id catalog.Identity) (decisionOutcome, decisionlog.Entry) {
	if d.opts.Exempt != nil && d.opts.Exempt.IsExempt(pi, sig) {
		return outcomeExempt, entryForWithoutPersistenceNoHash(decisionlog.DecisionAllow, "exempt_app", host, pi, sig, "")
	}
	switch d.opts.Allow.Decide(host) {
	case allowlist.Allow:
		if outcome, entry, blocked := d.bindDest(host, dstIP, pi, sig); blocked {
			return outcome, entry
		}
		return outcomeAllow, entryFor(decisionlog.DecisionAllow, "", host, pi, sig, decisionlog.TierDefault)
	case allowlist.Deny:
		return outcomeDeny, entryFor(decisionlog.DecisionDeny, "host_denylisted", host, pi, sig, decisionlog.TierDefault)
	default: // allowlist.Unknown
		var match catalog.MatchResult
		if d.opts.Catalog != nil {
			match = d.opts.Catalog.Lookup(id, host)
			if match.NeverHit {
				return outcomeDeny, entryFor(decisionlog.DecisionDeny, "catalog_never_hit", host, pi, sig, decisionlog.TierCatalogFact)
			}
			if match.StaleBinary && d.staleGraceAvailable(id.ExePath) {
				if outcome, entry, blocked := d.bindDest(host, dstIP, pi, sig); blocked {
					return outcome, entry
				}
				if d.recordPending(match.Entry, id, host) {
					return outcomeAllow, entryFor(decisionlog.DecisionAllow, "unratified_binary_grace", host, pi, sig, decisionlog.TierDefault)
				}
			}
			if match.Found && match.Authoritative {
				if outcome, entry, blocked := d.bindDest(host, dstIP, pi, sig); blocked {
					return outcome, entry
				}
				return outcomeAllow, entryFor(decisionlog.DecisionAllow, "catalog_fact", host, pi, sig, decisionlog.TierCatalogFact)
			}
		}
		if d.opts.Prompt == nil {
			// v0.1 fallback: no prompt configured → default-deny.
			return outcomeDeny, entryFor(decisionlog.DecisionDeny, "host_unknown_no_prompt", host, pi, sig, decisionlog.TierDefault)
		}
		req := prompt.Request{
			Proc:         pi,
			Host:         host,
			RegDom:       prompt.RegisteredDomain(host),
			CatalogMatch: match,
			Drift:        d.classifyDrift(host, pi, sig, id),
			Persistence:  attributePersistence(pi),
		}
		if d.opts.Explainer != nil {
			ectx, cancel := context.WithTimeout(context.Background(), explainTimeout)
			req.Opinion = explain.TryExplain(ectx, d.opts.Explainer, id, host, d.opts.Logger)
			cancel()
		}
		switch d.opts.Prompt.Decide(context.Background(), req) {
		case prompt.Allow:
			if outcome, entry, blocked := d.bindDest(host, dstIP, pi, sig); blocked {
				return outcome, entry
			}
			return outcomeAllow, entryFor(decisionlog.DecisionAllow, "user_allowed", host, pi, sig, decisionlog.TierPrompt)
		default:
			return outcomeDeny, entryFor(decisionlog.DecisionDeny, "user_denied_or_timeout", host, pi, sig, decisionlog.TierPrompt)
		}
	}
}

func (d *Daemon) staleGraceAvailable(exePath string) bool {
	counter, ok := d.opts.Pending.(pendingHashCounter)
	if !ok || exePath == "" {
		return true
	}
	n, err := counter.DistinctNewHashes(exePath)
	if err != nil {
		if d.opts.Logger != nil {
			d.opts.Logger.Errorf("pending: count distinct hashes for %s: %v", exePath, err)
		}
		return false
	}
	return n < maxGraceHashesPerPath
}

func (d *Daemon) recordPending(old catalog.Entry, id catalog.Identity, host string) bool {
	if d.opts.Pending == nil {
		return false
	}
	it := pending.Item{
		ExePath:   id.ExePath,
		Basename:  id.ExeBasename,
		OldSHA256: old.Identity.ExeSHA256,
		NewSHA256: id.ExeSHA256,
		Hosts:     []string{host},
	}
	if err := d.opts.Pending.Record(it); err != nil {
		if d.opts.Logger != nil {
			d.opts.Logger.Errorf("pending: record %s: %v", id.ExePath, err)
		}
		return false
	}
	return true
}

func (d *Daemon) identityFor(pi procid.ProcInfo, sig signature.SignedIdentity) catalog.Identity {
	base := filepath.Base(pi.Exe)
	if base == "" || base == "." {
		base = pi.Comm
	}
	id := catalog.Identity{ExeBasename: base, TeamID: sig.TeamID, BundleID: sig.BundleID}
	if d.hasher != nil && pi.Exe != "" {
		if real, sum, err := d.hasher.Hash(pi.Exe); err == nil {
			id.ExePath = real
			id.ExeSHA256 = sum
		}
	}
	return id
}

func exeSHA256(path string) string {
	if path == "" {
		return ""
	}
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	key := executableCacheKey(path, info)

	exeHashMu.Lock()
	if elem, ok := exeHashIndex[key]; ok {
		exeHashLRU.MoveToFront(elem)
		sum := elem.Value.(*exeHashEntry).sum
		exeHashMu.Unlock()
		return sum
	}
	exeHashMu.Unlock()

	sum := hashExecutable(path)
	if sum == "" {
		return ""
	}

	exeHashMu.Lock()
	defer exeHashMu.Unlock()
	if elem, ok := exeHashIndex[key]; ok {
		exeHashLRU.MoveToFront(elem)
		return elem.Value.(*exeHashEntry).sum
	}
	ent := &exeHashEntry{key: key, sum: sum}
	elem := exeHashLRU.PushFront(ent)
	exeHashIndex[key] = elem
	if exeHashLRU.Len() > maxExeHashCacheEntries {
		oldest := exeHashLRU.Back()
		exeHashLRU.Remove(oldest)
		delete(exeHashIndex, oldest.Value.(*exeHashEntry).key)
	}
	return sum
}

const maxExeHashCacheEntries = 256

type exeHashEntry struct {
	key string
	sum string
}

var (
	exeHashMu      sync.Mutex
	exeHashLRU     = list.New()
	exeHashIndex   = map[string]*list.Element{}
	hashExecutable = hashExecutableFile
)

func hashExecutableFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func baseExecutableCacheKey(path string, info os.FileInfo) string {
	return path + "\x00mtime=" + info.ModTime().UTC().Format(time.RFC3339Nano) + "\x00size=" + strconv.FormatInt(info.Size(), 10)
}

func (d *Daemon) classifyDrift(host string, pi procid.ProcInfo, sig signature.SignedIdentity, id catalog.Identity) drift.Event {
	exe := pi.Exe
	if id.ExePath != "" {
		exe = id.ExePath
	}
	entry := decisionlog.Entry{
		Host:      host,
		Exe:       exe,
		Comm:      pi.Comm,
		PName:     pi.PComm,
		ExeSHA256: id.ExeSHA256,
		TeamID:    sig.TeamID,
		SigValid:  sig.Valid,
		PID:       pi.PID,
		PPID:      pi.PPID,
		Argv:      pi.Argv,
		Cwd:       pi.Cwd,
	}
	if b := d.baseline.Load(); b != nil {
		ev := b.Classify(entry)
		if catalog.HasDecisionPin(id) {
			ev.Identity = id
		}
		return ev
	}
	return drift.Event{
		Class:     drift.ClassDrift,
		Reason:    drift.ReasonNovelPairing,
		Identity:  id,
		Host:      host,
		FirstSeen: timeNow(),
		Log:       entry,
	}
}

// bindDest enforces the SNI↔destination-IP binding. It returns blocked=true
// with a deny outcome+entry when a Binder is configured and the destination IP
// is not one the hostname resolves to (spoofed SNI) or resolution failed
// (fail-closed). blocked=false means "no binding configured, or the binding
// passed" — the caller proceeds to allow.
func (d *Daemon) bindDest(host string, dstIP net.IP, pi procid.ProcInfo, sig signature.SignedIdentity) (decisionOutcome, decisionlog.Entry, bool) {
	if d.opts.Binder == nil {
		return outcomeAllow, decisionlog.Entry{}, false
	}
	ok, err := d.opts.Binder.DestMatches(host, dstIP)
	switch {
	case err != nil:
		return outcomeDeny, entryFor(decisionlog.DecisionDeny, "sni_ip_unverifiable", host, pi, sig, decisionlog.TierDefault), true
	case !ok:
		return outcomeDeny, entryFor(decisionlog.DecisionDeny, "sni_ip_mismatch", host, pi, sig, decisionlog.TierDefault), true
	default:
		return outcomeAllow, decisionlog.Entry{}, false
	}
}

func (d *Daemon) handle(conn net.Conn) {
	defer conn.Close()
	conn.SetReadDeadline(timeNow().Add(clientHelloDeadline))

	dstIP, dstPort, err := d.opts.Kernel.OriginalDest(conn)
	if err != nil {
		_ = d.opts.Log.Write(entryFor(decisionlog.DecisionDeny, "original_dest_lookup_failed", "", procid.ProcInfo{}, signature.SignedIdentity{}, ""))
		return
	}

	// v0.2: lookup process identity + signature BEFORE reading client bytes,
	// so the exempt fast-path can splice without spending the SNI parse.
	var pi procid.ProcInfo
	if d.opts.ProcID != nil {
		pi, _ = d.opts.ProcID.LookupConn(conn)
	}
	var sig signature.SignedIdentity
	if d.opts.Signature != nil && pi.Exe != "" {
		sig, _ = d.opts.Signature.Verify(pi.Exe)
	}

	// Exempt fast-path: do not parse SNI, do not consult allowlist.
	if d.opts.Exempt != nil && d.opts.Exempt.IsExempt(pi, sig) {
		upstream, err := d.dial("tcp", net.JoinHostPort(dstIP.String(), itoa(dstPort)))
		if err != nil {
			entry := entryForWithoutPersistenceNoHash(decisionlog.DecisionDeny, "exempt_upstream_dial_failed: "+err.Error(), "", pi, sig, "")
			entry.DestIP, entry.DestPort = dstIP.String(), dstPort
			_ = d.opts.Log.Write(entry)
			return
		}
		entry := entryForWithoutPersistenceNoHash(decisionlog.DecisionAllow, "exempt_app", "", pi, sig, "")
		entry.DestIP, entry.DestPort = dstIP.String(), dstPort
		_ = d.opts.Log.Write(entry)
		conn.SetReadDeadline(timeZero())
		started := timeNow()
		up, down := spliceBoth(conn, upstream)
		d.writeFlow(entry.ConnID, entry, up, down, started)
		return
	}

	// Filtered path: read ClientHello, parse SNI, run decideBranch.
	buf := make([]byte, tlsparse.MaxClientHelloBytes)
	n, err := io.ReadAtLeast(conn, buf, 5)
	if err != nil {
		entry := entryFor(decisionlog.DecisionDeny, "read_clienthello_failed", "", pi, sig, "")
		entry.DestIP, entry.DestPort = dstIP.String(), dstPort
		_ = d.opts.Log.Write(entry)
		return
	}
	for n < len(buf) {
		conn.SetReadDeadline(timeNow().Add(50 * timeMillisecond))
		m, err := conn.Read(buf[n:])
		n += m
		if err != nil || m == 0 {
			break
		}
	}
	conn.SetReadDeadline(timeZero())

	host, err := tlsparse.ParseSNI(buf[:n])
	if err != nil {
		entry := entryFor(decisionlog.DecisionDeny, "sni_parse_failed: "+err.Error(), "", pi, sig, "")
		entry.DestIP, entry.DestPort = dstIP.String(), dstPort
		_ = d.opts.Log.Write(entry)
		return
	}

	outcome, entry := d.decideBranch(host, dstIP, pi, sig)
	entry.DestIP, entry.DestPort = dstIP.String(), dstPort
	outcome, entry = d.finalizeOutcome(outcome, entry)

	switch outcome {
	case outcomeAllow:
		upstream, err := d.dial("tcp", net.JoinHostPort(dstIP.String(), itoa(dstPort)))
		if err != nil {
			if d.opts.ObserveOnly {
				if entry.Reason != "" {
					entry.Reason = "net_error: upstream_dial_failed after " + entry.Reason + ": " + err.Error()
				} else {
					entry.Reason = "net_error: upstream_dial_failed: " + err.Error()
				}
				_ = d.opts.Log.Write(entry)
				return
			}
			entry.Action = "deny"
			entry.Decision = decisionlog.DecisionDeny
			entry.Reason = "upstream_dial_failed: " + err.Error()
			_ = d.opts.Log.Write(entry)
			return
		}
		// Replay the bytes we already read from the client to the upstream.
		if _, err := upstream.Write(buf[:n]); err != nil {
			upstream.Close()
			if d.opts.ObserveOnly {
				if entry.Reason != "" {
					entry.Reason = "net_error: upstream_write_failed after " + entry.Reason + ": " + err.Error()
				} else {
					entry.Reason = "net_error: upstream_write_failed: " + err.Error()
				}
			} else {
				entry.Action = "deny"
				entry.Decision = decisionlog.DecisionDeny
				entry.Reason = "upstream_write_failed: " + err.Error()
			}
			_ = d.opts.Log.Write(entry)
			return
		}
		_ = d.opts.Log.Write(entry)
		started := timeNow()
		up, down := spliceBoth(conn, upstream)
		d.writeFlow(entry.ConnID, entry, up, down, started)
	default: // outcomeDeny (outcomeExempt is handled by fast-path above)
		_ = d.opts.Log.Write(entry)
		// Close → TCP RST/FIN to client; client's TLS handshake fails.
	}
}
