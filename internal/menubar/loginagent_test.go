//go:build darwin

package menubar

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoginAgentPlist_HasArgsAndRunAtLoad(t *testing.T) {
	xml := loginAgentPlist([]string{"/usr/local/bin/egress-guard-bar"})
	if !strings.Contains(xml, "<string>/usr/local/bin/egress-guard-bar</string>") {
		t.Errorf("missing program arg:\n%s", xml)
	}
	if !strings.Contains(xml, "<key>RunAtLoad</key>") || !strings.Contains(xml, "<true/>") {
		t.Errorf("missing RunAtLoad true:\n%s", xml)
	}
	if !strings.Contains(xml, menubarAgentLabel) {
		t.Errorf("missing label:\n%s", xml)
	}
}

func TestInstallAndRemoveLoginAgent_WritesFile(t *testing.T) {
	dir := t.TempDir()
	path, err := installLoginAgentFile(dir, []string{"/usr/local/bin/egress-guard-bar"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("plist not written: %v", err)
	}
	if got := filepath.Base(path); got != menubarAgentLabel+".plist" {
		t.Errorf("plist name = %q", got)
	}
	if !LoginAgentInstalled(dir) {
		t.Errorf("LoginAgentInstalled = false after write")
	}
	if err := removeLoginAgentFile(dir); err != nil {
		t.Fatal(err)
	}
	if LoginAgentInstalled(dir) {
		t.Errorf("LoginAgentInstalled = true after remove")
	}
}
