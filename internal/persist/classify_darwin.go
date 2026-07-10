//go:build darwin

package persist

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/byliu-labs/egress-guard/internal/procid"
)

const shelloutTimeout = 2 * time.Second
const maxAncestorDepth = 12

type ancestor struct {
	pid  int
	ppid int
	comm string
}

var knownShells = map[string]bool{
	"zsh": true, "bash": true, "sh": true, "fish": true, "tcsh": true, "csh": true, "dash": true,
}

var backgroundTokens = []string{"&", "nohup", "disown", "setsid"}
var rcFileNames = []string{".zshrc", ".zprofile", ".bash_profile", ".bashrc", ".profile"}

func classify(pi procid.ProcInfo) (SourceKind, string, error) {
	chain, err := ancestorChain(pi.PID, pi.PPID)
	if err != nil {
		return KindUnknown, "", fmt.Errorf("ancestor chain: %w", err)
	}
	launchdPIDs, _ := launchdPIDLabels()
	if kind, label := classifyChain(chain, launchdPIDs); kind != "" {
		if kind == KindCron {
			label = cronLabelFor(chain)
		}
		return kind, label, nil
	}
	if !hasShellAncestor(chain) {
		return KindUnknown, "", nil
	}
	if label, ok := matchRCHook(chain); ok {
		return KindRCHook, label, nil
	}
	return KindSession, "", nil
}

func ancestorChain(pid, ppid int) ([]ancestor, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shelloutTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ps", "-axo", "pid=,ppid=,comm=")
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ps snapshot: %w", err)
	}

	byPID := map[int]ancestor{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		p, err1 := strconv.Atoi(fields[0])
		pp, err2 := strconv.Atoi(fields[1])
		if err1 != nil || err2 != nil {
			continue
		}
		byPID[p] = ancestor{pid: p, ppid: pp, comm: filepath.Base(fields[2])}
	}

	var chain []ancestor
	visited := map[int]bool{}
	cur := pid
	if a, ok := byPID[cur]; ok {
		chain = append(chain, a)
		visited[cur] = true
		cur = a.ppid
	} else if ppid != 0 {
		cur = ppid
	} else {
		return nil, fmt.Errorf("pid %d not found in process table", pid)
	}
	for i := 0; i < maxAncestorDepth && cur > 1; i++ {
		if visited[cur] {
			break
		}
		a, ok := byPID[cur]
		if !ok {
			break
		}
		chain = append(chain, a)
		visited[cur] = true
		cur = a.ppid
	}
	return chain, nil
}

func launchdPIDLabels() (map[int]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shelloutTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "launchctl", "list")
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("launchctl list: %w", err)
	}
	result := map[int]string{}
	for i, line := range strings.Split(string(out), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		result[pid] = fields[len(fields)-1]
	}
	return result, nil
}

func classifyChain(chain []ancestor, launchdPIDs map[int]string) (SourceKind, string) {
	for _, a := range chain {
		if label, ok := launchdPIDs[a.pid]; ok {
			return KindLaunchd, label
		}
	}
	for _, a := range chain {
		if strings.EqualFold(a.comm, "cron") || strings.EqualFold(a.comm, "crond") {
			return KindCron, ""
		}
	}
	return "", ""
}

func hasShellAncestor(chain []ancestor) bool {
	for _, a := range chain {
		if knownShells[strings.ToLower(a.comm)] {
			return true
		}
	}
	return false
}

func cronLabelFor(chain []ancestor) string {
	for i, a := range chain {
		if !strings.EqualFold(a.comm, "cron") && !strings.EqualFold(a.comm, "crond") {
			continue
		}
		if i == 0 {
			break
		}
		child := chain[i-1]
		args := psArgs(child.pid)
		if line, ok := matchCrontabLine(args); ok {
			return line
		}
		if args != "" {
			return "cron (unmatched entry): " + args
		}
	}
	return "cron (unmatched entry)"
}

func psArgs(pid int) string {
	ctx, cancel := context.WithTimeout(context.Background(), shelloutTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ps", "-o", "args=", "-p", strconv.Itoa(pid))
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func matchCrontabLine(args string) (string, bool) {
	if args == "" {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), shelloutTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "crontab", "-l")
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(args, trimmed) || strings.Contains(trimmed, args) {
			return trimmed, true
		}
	}
	return "", false
}

func matchRCHook(chain []ancestor) (string, bool) {
	home, err := resolveHome()
	if err != nil {
		return "", false
	}
	files := map[string]string{}
	for _, name := range rcFileNames {
		b, err := os.ReadFile(filepath.Join(home, name))
		if err != nil {
			continue
		}
		files[name] = string(b)
	}
	return matchRCHookContent(chain, files)
}

func matchRCHookContent(chain []ancestor, files map[string]string) (string, bool) {
	for _, a := range chain {
		name := strings.ToLower(a.comm)
		if name == "" {
			continue
		}
		for rc, content := range files {
			for _, line := range strings.Split(content, "\n") {
				lower := strings.ToLower(line)
				if !strings.Contains(lower, name) {
					continue
				}
				if hasBackgroundToken(lower) {
					return rc + ": " + strings.TrimSpace(line), true
				}
			}
		}
	}
	return "", false
}

func hasBackgroundToken(line string) bool {
	for _, tok := range backgroundTokens {
		if strings.Contains(line, tok) {
			return true
		}
	}
	return false
}
