package nebridge

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/byliu-labs/egress-guard/internal/decisionlog"
	"github.com/byliu-labs/egress-guard/internal/procid"
	"github.com/byliu-labs/egress-guard/internal/signature"
	"github.com/byliu-labs/egress-guard/internal/tlsparse"
)

// Decider is satisfied by daemon.Daemon. It returns the audit entry for one
// decision; Server persists that entry after adding bridge destination data.
type Decider interface {
	Decide(host string, dstIP net.IP, pi procid.ProcInfo, sig signature.SignedIdentity) decisionlog.Entry
}

// Server turns one NEFilter request into one decision response.
type Server struct {
	Decider  Decider
	Resolver IdentityResolver
	Log      *decisionlog.Writer
}

// Listen creates a Unix-domain listener. New socket directories are private;
// existing parent directories are left unchanged and the socket itself is 0600.
func Listen(socketPath string) (net.Listener, error) {
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("nebridge: create socket directory: %w", err)
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
		req, err := DecodeRequest(conn)
		if err != nil {
			return
		}
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

		entry := s.Decider.Decide(host, req.DstIP, pi, sig)
		entry.DestIP = req.DstIP.String()
		entry.DestPort = req.DstPort
		_ = s.Log.Write(entry)

		verdict := VerdictAllow
		if entry.Decision == decisionlog.DecisionDeny {
			verdict = VerdictDrop
		}
		_ = EncodeResponse(conn, Response{Verdict: verdict, Host: host, Reason: entry.Reason})
	}
}

func (s *Server) drop(conn net.Conn, host string, req Request, reason string) {
	entry := decisionlog.Entry{
		Decision: decisionlog.DecisionDeny,
		Action:   string(decisionlog.DecisionDeny),
		Reason:   reason,
		Host:     host,
		DestIP:   req.DstIP.String(),
		DestPort: req.DstPort,
	}
	_ = s.Log.Write(entry)
	_ = EncodeResponse(conn, Response{Verdict: VerdictDrop, Host: host, Reason: reason})
}
