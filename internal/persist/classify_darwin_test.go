//go:build darwin

package persist

import (
	"os"
	"strings"
	"testing"
)

func TestAncestorChain_IncludesSelf(t *testing.T) {
	chain, err := ancestorChain(os.Getpid(), os.Getppid())
	if err != nil {
		skipHostProcessDenied(t, err)
		t.Fatalf("ancestorChain: %v", err)
	}
	if len(chain) == 0 {
		t.Fatal("chain is empty")
	}
	if chain[0].pid != os.Getpid() {
		t.Errorf("chain[0].pid = %d, want %d (self)", chain[0].pid, os.Getpid())
	}
	t.Logf("chain: %+v", chain)
}

func TestAncestorChain_BoundedDepth(t *testing.T) {
	chain, err := ancestorChain(os.Getpid(), os.Getppid())
	if err != nil {
		skipHostProcessDenied(t, err)
		t.Fatalf("ancestorChain: %v", err)
	}
	if len(chain) > maxAncestorDepth+1 {
		t.Errorf("chain length %d exceeds maxAncestorDepth+1 (%d)", len(chain), maxAncestorDepth+1)
	}
}

func TestLaunchdPIDLabels_NoError(t *testing.T) {
	labels, err := launchdPIDLabels()
	if err != nil {
		skipHostProcessDenied(t, err)
		t.Fatalf("launchdPIDLabels: %v", err)
	}
	t.Logf("observed %d running launchd jobs", len(labels))
	for pid, label := range labels {
		if pid <= 0 {
			t.Errorf("non-positive pid %d in launchd table (label %q)", pid, label)
		}
		if label == "" {
			t.Errorf("empty label for pid %d", pid)
		}
	}
}

func skipHostProcessDenied(t *testing.T, err error) {
	t.Helper()
	msg := err.Error()
	if strings.Contains(msg, "operation not permitted") ||
		(strings.Contains(msg, "launchctl list: exit status 1") && os.Getenv("CODEX_SANDBOX") != "") {
		t.Skipf("host process inspection blocked by sandbox: %v", err)
	}
}

func TestClassifyChain_MatchesLaunchdByPID(t *testing.T) {
	chain := []ancestor{
		{pid: 500, ppid: 1, comm: "curl"},
		{pid: 1, ppid: 0, comm: "launchd"},
	}
	launchdPIDs := map[int]string{500: "com.example.beacon"}

	kind, label := classifyChain(chain, launchdPIDs)
	if kind != KindLaunchd {
		t.Fatalf("kind = %q, want %q", kind, KindLaunchd)
	}
	if label != "com.example.beacon" {
		t.Errorf("label = %q, want %q", label, "com.example.beacon")
	}
}

func TestClassifyChain_MatchesCron(t *testing.T) {
	chain := []ancestor{
		{pid: 700, ppid: 650, comm: "curl"},
		{pid: 650, ppid: 60, comm: "sh"},
		{pid: 60, ppid: 1, comm: "cron"},
	}
	kind, _ := classifyChain(chain, nil)
	if kind != KindCron {
		t.Fatalf("kind = %q, want %q", kind, KindCron)
	}
}

func TestClassifyChain_NoMatchReturnsZeroValue(t *testing.T) {
	chain := []ancestor{
		{pid: 900, ppid: 800, comm: "curl"},
		{pid: 800, ppid: 1, comm: "zsh"},
	}
	kind, label := classifyChain(chain, nil)
	if kind != "" || label != "" {
		t.Errorf("classifyChain = (%q,%q), want zero values", kind, label)
	}
}

func TestHasShellAncestor(t *testing.T) {
	cases := []struct {
		name  string
		chain []ancestor
		want  bool
	}{
		{"zsh ancestor", []ancestor{{comm: "curl"}, {comm: "zsh"}}, true},
		{"bash ancestor case-insensitive", []ancestor{{comm: "Bash"}}, true},
		{"no shell ancestor", []ancestor{{comm: "curl"}, {comm: "launchd"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hasShellAncestor(c.chain); got != c.want {
				t.Errorf("hasShellAncestor(%+v) = %v, want %v", c.chain, got, c.want)
			}
		})
	}
}

func TestCronLabelFor_FallsBackWhenNoCrontabMatch(t *testing.T) {
	chain := []ancestor{
		{pid: os.Getpid(), ppid: os.Getppid(), comm: "persist.test"},
		{pid: os.Getppid(), ppid: 1, comm: "cron"},
	}
	label := cronLabelFor(chain)
	if label == "" {
		t.Fatal("cronLabelFor returned empty label")
	}
	if !strings.HasPrefix(label, "cron ") {
		t.Errorf("label = %q, want it to start with %q", label, "cron ")
	}
	t.Logf("label: %s", label)
}

func TestMatchRCHookContent_MatchesBackgroundedCommand(t *testing.T) {
	chain := []ancestor{{pid: 1, ppid: 0, comm: "beacon-agent"}}
	files := map[string]string{
		".zshrc": "export PATH=/usr/local/bin:$PATH\nnohup beacon-agent --daemonize &\n",
	}
	label, ok := matchRCHookContent(chain, files)
	if !ok {
		t.Fatal("expected a match")
	}
	if !strings.Contains(label, ".zshrc") || !strings.Contains(label, "beacon-agent") {
		t.Errorf("label = %q, want it to reference the rc file and command", label)
	}
}

func TestMatchRCHookContent_IgnoresPlainMentionWithoutBackgrounding(t *testing.T) {
	chain := []ancestor{{pid: 1, ppid: 0, comm: "curl"}}
	files := map[string]string{".zshrc": "alias c=curl\n"}
	_, ok := matchRCHookContent(chain, files)
	if ok {
		t.Fatal("plain mention without a backgrounding token must not match")
	}
}

func TestMatchRCHookContent_NoMatchWhenAbsent(t *testing.T) {
	chain := []ancestor{{pid: 1, ppid: 0, comm: "curl"}}
	files := map[string]string{".zshrc": "export EDITOR=vim\n"}
	_, ok := matchRCHookContent(chain, files)
	if ok {
		t.Fatal("expected no match")
	}
}
