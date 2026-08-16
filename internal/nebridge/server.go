package nebridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
	"github.com/byliu-labs/egress-guard/internal/tlsparse"
)

// Decider is satisfied by daemon.Daemon. It returns the audit entry for one
// decision; Server persists that entry after adding bridge destination data.
type Decider interface {
	Decide(host string, dstIP net.IP, pi procid.ProcInfo, sig signature.SignedIdentity) (decisionlog.Decision, decisionlog.Entry)
}

// Server turns one NEFilter request into one decision response.
type Server struct {
	Decider       Decider
	Resolver      IdentityResolver
	Log           *decisionlog.Writer
	FrameDeadline time.Duration
}

const defaultBridgeFrameDeadline = 5 * time.Second

// Listen creates a Unix-domain listener in a private directory owned by this
// process's effective user. It rejects pre-existing unsafe directories instead
// of repairing or following them, then limits stale-path removal to sockets.
func Listen(socketPath string) (net.Listener, error) {
	dir := filepath.Dir(socketPath)
	if err := ensureSocketDirectory(dir); err != nil {
		return nil, err
	}
	if err := removeStaleSocket(socketPath); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("nebridge: listen on %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("nebridge: set socket permissions: %w", err)
	}
	return ln, nil
}

func ensureSocketDirectory(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
		return fmt.Errorf("nebridge: create socket directory %s: %w", dir, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("nebridge: inspect socket directory %s: %w", dir, err)
	}
	return validateSocketDirectory(dir, info)
}

func validateSocketDirectory(dir string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("nebridge: socket directory is a symlink: %s", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("nebridge: socket directory is not a directory: %s", dir)
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		return fmt.Errorf("nebridge: socket directory %s has mode %o, want 700", dir, mode)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("nebridge: cannot determine socket directory owner: %s", dir)
	}
	if owner := int(stat.Uid); owner != os.Geteuid() {
		return fmt.Errorf("nebridge: socket directory %s is owned by euid %d, want %d", dir, owner, os.Geteuid())
	}
	return nil
}

func removeStaleSocket(socketPath string) error {
	info, err := os.Lstat(socketPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("nebridge: inspect socket path: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("nebridge: socket path exists and is not a socket: %s", socketPath)
	}
	if err := os.Remove(socketPath); err != nil {
		return fmt.Errorf("nebridge: remove stale socket: %w", err)
	}
	return nil
}

// Serve accepts bridge connections until ctx is cancelled or the listener
// fails. Each connection carries one or more requests.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
		case <-done:
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("nebridge: accept: %w", err)
		}
		go s.handleConn(conn)
	}
}

// handleConn serves requests until the client closes the connection.
func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	for {
		if err := conn.SetReadDeadline(time.Now().Add(s.frameDeadline())); err != nil {
			s.logDeny("", 0, "", "deadline_failed: "+err.Error())
			return
		}
		req, err := DecodeRequest(conn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			reason := "frame_decode_failed: " + err.Error()
			s.logDeny("", 0, "", reason)
			s.writeResponse(conn, Response{Verdict: VerdictDrop, Reason: reason})
			return
		}
		_ = conn.SetReadDeadline(time.Time{})
		host, err := tlsparse.ParseSNI(req.ClientHello)
		if err != nil {
			s.drop(conn, "", req, "sni_parse_failed: "+err.Error())
			continue
		}
		pi, sig, err := s.Resolver.Resolve(req.AuditToken)
		if err != nil {
			s.drop(conn, host, req, "identity_resolve_failed: "+err.Error())
			continue
		}

		dec, entry := s.Decider.Decide(host, req.DstIP, pi, sig)
		entry.DestIP = req.DstIP.String()
		entry.DestPort = req.DstPort
		entry = logEntryForDecision(dec, entry)
		if err := s.Log.Write(entry); err != nil {
			s.drop(conn, host, req, "log_write_failed: "+err.Error())
			continue
		}
		s.writeResponse(conn, Response{Verdict: verdictFor(dec), Host: host, Reason: entry.Reason})
	}
}

func (s *Server) drop(conn net.Conn, host string, req Request, reason string) {
	entry := decisionlog.Entry{
		Decision:  decisionlog.DecisionDeny,
		Action:    string(decisionlog.DecisionDeny),
		TrustTier: decisionlog.TierDefault,
		Reason:    reason,
		Host:      host,
		DestIP:    req.DstIP.String(),
		DestPort:  req.DstPort,
	}
	_ = s.Log.Write(entry)
	s.writeResponse(conn, Response{Verdict: VerdictDrop, Host: host, Reason: reason})
}

func (s *Server) logDeny(destIP string, destPort int, host, reason string) {
	_ = s.Log.Write(decisionlog.Entry{
		Decision:  decisionlog.DecisionDeny,
		Action:    string(decisionlog.DecisionDeny),
		TrustTier: decisionlog.TierDefault,
		Reason:    reason,
		Host:      host,
		DestIP:    destIP,
		DestPort:  destPort,
	})
}

// verdictFor maps a decision to a wire verdict. Allow is an explicit
// whitelist, never an else-branch: an unrecognized decision state cannot
// authorize egress.
func verdictFor(dec decisionlog.Decision) Verdict {
	switch dec {
	case decisionlog.DecisionAllow, decisionlog.DecisionObserve:
		return VerdictAllow
	default:
		return VerdictDrop
	}
}

func logEntryForDecision(dec decisionlog.Decision, entry decisionlog.Entry) decisionlog.Entry {
	switch dec {
	case decisionlog.DecisionAllow, decisionlog.DecisionObserve, decisionlog.DecisionDeny:
		return entry
	default:
		entry.Decision = decisionlog.DecisionDeny
		entry.Action = string(decisionlog.DecisionDeny)
		entry.Reason = invalidDecisionReason(dec)
		return entry
	}
}

func invalidDecisionReason(decision decisionlog.Decision) string {
	if decision == "" {
		return "invalid_decision: empty"
	}
	return fmt.Sprintf("invalid_decision: %q", decision)
}

func (s *Server) writeResponse(conn net.Conn, response Response) {
	_ = conn.SetWriteDeadline(time.Now().Add(s.frameDeadline()))
	_ = EncodeResponse(conn, response)
	_ = conn.SetWriteDeadline(time.Time{})
}

func (s *Server) frameDeadline() time.Duration {
	if s.FrameDeadline > 0 {
		return s.FrameDeadline
	}
	return defaultBridgeFrameDeadline
}
