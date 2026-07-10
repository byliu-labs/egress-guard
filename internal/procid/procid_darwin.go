//go:build darwin

package procid

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// shelloutTimeout caps every codesign / lsof / ps / dpkg / rpm invocation.
// 2s is generous: codesign on a real binary is <100ms, lsof <200ms, dpkg/rpm
// <100ms. The cap exists to prevent one stuck shellout from wedging the
// per-connection goroutine and starving the listener.
const shelloutTimeout = 2 * time.Second

func defaultLookup() Lookup { return &darwinLookup{} }

type darwinLookup struct{}

// LookupConn finds the client process by matching the connection's REMOTE
// 4-tuple (= client process's LOCAL socket) against `lsof`'s established
// TCP table. proc_pidpath then resolves the pid to an executable path.
//
// Why lsof: darwin has no equivalent of linux's SO_PEERCRED for AF_INET, and
// LOCAL_PEERPID is AF_UNIX-only. proc_pidfdinfo would let us avoid the shellout
// but requires walking every pid × every fd; lsof does that walk in C and is
// part of the base system. Cost is ~50-200ms per call; only paid on
// unknown-host paths (allowlisted hosts hit the daemon's faster path).
func (d *darwinLookup) LookupConn(conn net.Conn) (ProcInfo, error) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return ProcInfo{}, errors.New("procid darwin: expected *net.TCPConn")
	}
	rAddr, _ := tcp.RemoteAddr().(*net.TCPAddr)
	lAddr, _ := tcp.LocalAddr().(*net.TCPAddr)
	if rAddr == nil || lAddr == nil {
		return ProcInfo{}, errors.New("procid darwin: connection missing addrs")
	}

	pid, comm, err := lsofLookup(rAddr, lAddr)
	if err != nil {
		return ProcInfo{}, err
	}
	pi := ProcInfo{PID: pid, Comm: comm}

	if exe, err := procPidPath(pid); err == nil {
		pi.Exe = exe
		pi.Comm = filepath.Base(exe)
	}
	pi.PPID, _ = parentPID(pid)
	if pi.PPID != 0 {
		if pexe, err := procPidPath(pi.PPID); err == nil {
			pi.PComm = filepath.Base(pexe)
		}
	}
	pi.Cwd, _ = procPidCwd(pid)
	pi.Argv, _ = psArgv(pid)
	return pi, nil
}

// lsofLookup runs `lsof -nP -iTCP -sTCP:ESTABLISHED -F pcn` and parses for an
// ESTABLISHED entry whose NAME matches `<rAddr>-><lAddr>` (i.e., the client
// process's local-side socket points at the daemon's listener). Returns
// pid + command name; ProcInfo's other fields are filled by the caller.
//
// The -F output format is one field per line, prefixed by a single character:
//
//	p<pid>
//	c<command>
//	f<fd>
//	t<type>     ("IPv4")
//	P<proto>    ("TCP")
//	n<name>     ("127.0.0.1:55555->127.0.0.1:8443")
//
// `f`/`t`/`P`/`n` repeat per fd within the same `p`/`c` process block.
func lsofLookup(rAddr, lAddr *net.TCPAddr) (int, string, error) {
	target := net.JoinHostPort(rAddr.IP.String(), strconv.Itoa(rAddr.Port)) +
		"->" +
		net.JoinHostPort(lAddr.IP.String(), strconv.Itoa(lAddr.Port))

	ctx, cancel := context.WithTimeout(context.Background(), shelloutTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-F", "pcn")
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		return 0, "", fmt.Errorf("lsof: %w", err)
	}

	var curPID int
	var curComm string
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			pid, perr := strconv.Atoi(line[1:])
			if perr != nil {
				continue
			}
			curPID = pid
			curComm = ""
		case 'c':
			curComm = line[1:]
		case 'n':
			if line[1:] == target {
				return curPID, curComm, nil
			}
		}
	}
	return 0, "", fmt.Errorf("procid darwin: no process owns %s", target)
}

// procPidPath returns the absolute exe path for a darwin pid via
// `lsof -a -d txt -p PID -F n`. The `txt` fd is the running executable;
// lsof's -F n machine-readable format prints `n<absolute-path>` for each
// matching fd. Returns "" if lsof fails or no txt fd is found.
//
// We avoid the raw __proc_info syscall here: PROC_INFO_CALL_PIDPATH's
// selector / argument layout has shifted across xnu versions and the bare
// syscall returns EINVAL with the values that worked in older code. lsof is
// part of the base macOS install and the format is stable.
func procPidPath(pid int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shelloutTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "lsof", "-a", "-d", "txt", "-p", strconv.Itoa(pid), "-F", "n")
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("lsof txt for pid %d: %w", pid, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "n") && strings.HasPrefix(line[1:], "/") {
			return line[1:], nil
		}
	}
	return "", fmt.Errorf("procid darwin: no txt fd for pid %d", pid)
}

// parentPID via `ps -o ppid= -p N`. Best-effort.
func parentPID(pid int) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shelloutTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ps", "-o", "ppid=", "-p", strconv.Itoa(pid))
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	var ppid int
	_, err = fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &ppid)
	return ppid, err
}

// procPidCwd via `lsof -a -d cwd -Fn -p N`. Best-effort.
func procPidCwd(pid int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shelloutTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "lsof", "-a", "-d", "cwd", "-Fn", "-p", strconv.Itoa(pid))
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "n") {
			return strings.TrimPrefix(line, "n"), nil
		}
	}
	return "", nil
}

// psArgv via `ps -o args= -p N`. Best-effort; truncated entries acceptable.
func psArgv(pid int) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shelloutTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ps", "-o", "args=", "-p", strconv.Itoa(pid))
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	line := strings.TrimSpace(string(out))
	if line == "" {
		return nil, nil
	}
	return strings.Fields(line), nil
}
