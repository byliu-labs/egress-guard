//go:build darwin

package menubar

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/byliu-labs/egress-guard/internal/cli"
	"github.com/getlantern/systray"
)

const recentSlots = 5

type menu struct {
	status     *systray.MenuItem
	recent     []*systray.MenuItem
	allowLast  *systray.MenuItem
	pause      *systray.MenuItem
	resume     *systray.MenuItem
	startLogin *systray.MenuItem

	// lastHost is written by refresh() on the ticker goroutine and read by
	// the click handler on another goroutine, so it needs its own guard.
	mu       sync.Mutex
	lastHost string
}

func (m *menu) setLastHost(host string) {
	m.mu.Lock()
	m.lastHost = host
	m.mu.Unlock()
}

func (m *menu) getLastHost() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastHost
}

func bundleResourceDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	macos := filepath.Dir(exe)
	res := filepath.Join(filepath.Dir(macos), "Resources")
	if _, err := os.Stat(res); err == nil {
		return res
	}
	return filepath.Dir(exe)
}

// Run starts the menu-bar event loop. It blocks until the user quits.
func Run() {
	systray.Run(onReady, func() {})
}

func onReady() {
	m := &menu{}

	if FirstRunNeeded() && confirmInstall() {
		if err := RunAdmin(AdminInstallScript(bundleResourceDir())); err == nil {
			_ = execFn(installedBinPath, "enable")
			_, _ = InstallLoginAgent("")
		}
	}

	// macOS menu-bar tooltips are unreliable, so the status can't live only in
	// SetTooltip — surface it as an always-visible, non-clickable first row so
	// the user reads WHY (e.g. a TUN proxy is bypassing enforcement) on open.
	m.status = systray.AddMenuItem("", "current protection status")
	m.status.Disable()
	systray.AddSeparator()

	m.buildStatusSlots()
	systray.AddSeparator()
	m.allowLast = systray.AddMenuItem("Allow last blocked host", "Add the newest blocked host to the allowlist")
	m.allowLast.Disable()
	systray.AddSeparator()
	m.pause = systray.AddMenuItem("Pause protection", "Flush the pf anchor")
	m.resume = systray.AddMenuItem("Resume protection", "Reinstall the pf anchor")
	systray.AddSeparator()
	m.startLogin = systray.AddMenuItem("Start at login", "Launch the menu bar automatically")
	if LoginAgentInstalled("") {
		m.startLogin.Check()
	}
	systray.AddSeparator()
	mUninstall := systray.AddMenuItem("Uninstall egress-guard", "Remove protection and all components")
	mQuit := systray.AddMenuItem("Quit", "Quit the menu bar (protection keeps running)")

	m.wireClicks(mUninstall, mQuit)
	m.refresh()

	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for range t.C {
			m.refresh()
		}
	}()
}

func (m *menu) buildStatusSlots() {
	m.recent = make([]*systray.MenuItem, recentSlots)
	for i := range m.recent {
		it := systray.AddMenuItem("", "recent block")
		it.Disable()
		it.Hide()
		m.recent[i] = it
	}
}

func (m *menu) refresh() {
	r := cli.Probe()
	title, tip := Glyph(r)
	systray.SetTitle(title)
	systray.SetTooltip(tip)
	m.status.SetTitle(StatusLine(r))

	blocks, _ := RecentBlocks(recentSlots)
	for i, it := range m.recent {
		if i < len(blocks) {
			it.SetTitle(blocks[i].Display)
			it.Show()
		} else {
			it.Hide()
		}
	}
	// Only offer "Allow <host>" when the newest block carries a real host.
	// A host-less entry (unknown host) would produce an "Allow (unknown host)"
	// item that AllowHost rejects as an invalid host — a silent no-op.
	if n := len(blocks); n > 0 && blocks[n-1].Host != "" {
		host := blocks[n-1].Host
		m.setLastHost(host)
		m.allowLast.SetTitle("Allow " + host)
		m.allowLast.Enable()
		return
	}
	m.setLastHost("")
	m.allowLast.SetTitle("Allow last blocked host")
	m.allowLast.Disable()
}

func (m *menu) wireClicks(mUninstall, mQuit *systray.MenuItem) {
	go func() {
		for {
			select {
			case <-m.allowLast.ClickedCh:
				if host := m.getLastHost(); host != "" {
					_ = AllowHost(host)
				}
			case <-m.pause.ClickedCh:
				_ = RunAdmin(PauseScript())
			case <-m.resume.ClickedCh:
				_ = RunAdmin(ResumeScript())
			case <-m.startLogin.ClickedCh:
				if LoginAgentInstalled("") {
					_ = RemoveLoginAgent("")
					m.startLogin.Uncheck()
				} else {
					_, _ = InstallLoginAgent("")
					m.startLogin.Check()
				}
			case <-mUninstall.ClickedCh:
				_ = execFn(installedBinPath, "uninstall")
				_ = RemoveLoginAgent("")
				_ = RunAdmin(UninstallScriptRoot())
				systray.Quit()
			case <-mQuit.ClickedCh:
				systray.Quit()
			}
		}
	}()
}
