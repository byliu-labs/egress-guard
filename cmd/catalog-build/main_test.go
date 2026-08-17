package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/catalogsig"
	"github.com/byliu-labs/egress-guard/internal/exempt"
)

func TestRun_BuildOfflineRoundTrips(t *testing.T) {
	out := filepath.Join(t.TempDir(), "catalog-baseline.toml")
	if err := run([]string{"build", "--baseline", "../../catalog/baseline", "--out", out}); err != nil {
		t.Fatalf("run build: %v", err)
	}
	c, err := catalog.LoadFile(out)
	if err != nil {
		t.Fatalf("compiled output does not load: %v", err)
	}
	if !c.HasHost("registry.npmjs.org") {
		t.Error("compiled catalog missing registry.npmjs.org")
	}
}

func TestRun_RefreshUsesKnownGoodFragments(t *testing.T) {
	out := filepath.Join(t.TempDir(), "catalog-baseline.toml")
	if err := run([]string{"refresh", "--baseline", "../../catalog/baseline", "--out", out}); err != nil {
		t.Fatalf("run refresh: %v", err)
	}
	c, err := catalog.LoadFile(out)
	if err != nil {
		t.Fatalf("refreshed output does not load: %v", err)
	}
	if !c.HasHost("pypi.org") {
		t.Error("refreshed catalog missing pypi.org")
	}
}

func TestRun_BuildReusesIssuedAtWhenOutputIsUnchanged(t *testing.T) {
	out := filepath.Join(t.TempDir(), "catalog-baseline.toml")
	if err := run([]string{"build", "--baseline", "../../catalog/baseline", "--out", out}); err != nil {
		t.Fatalf("first build: %v", err)
	}
	first, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read first output: %v", err)
	}
	if err := run([]string{"build", "--baseline", "../../catalog/baseline", "--out", out}); err != nil {
		t.Fatalf("second build: %v", err)
	}
	second, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read second output: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("unchanged fragments produced byte-different output")
	}
}

func TestRun_EmbedExemptWritesFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "defaults_embedded.toml")
	if err := run([]string{"embed-exempt", "--exempt", "../../catalog/exempt", "--out", out}); err != nil {
		t.Fatalf("run embed-exempt: %v", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read embedded exempt output: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("embed-exempt produced an empty file")
	}
	if _, err := exempt.LoadFromString(string(b)); err != nil {
		t.Fatalf("embedded exempt output does not parse: %v", err)
	}
}

func TestRun_SignWithKeyFileProducesVerifiableArtifact(t *testing.T) {
	dir := t.TempDir()
	catalogPath := filepath.Join(dir, "catalog-baseline.toml")
	if err := run([]string{"build", "--baseline", "../../catalog/baseline", "--out", catalogPath}); err != nil {
		t.Fatalf("run build: %v", err)
	}
	pub, priv, err := catalogsig.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyPath := filepath.Join(dir, "catalog-signing.key")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(priv)), 0o600); err != nil {
		t.Fatalf("write signing key: %v", err)
	}
	sigPath := filepath.Join(dir, "catalog-baseline.toml.sig")
	if err := run([]string{"sign", "--in", catalogPath, "--key", keyPath}); err != nil {
		t.Fatalf("run sign: %v", err)
	}

	data, err := os.ReadFile(catalogPath)
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	sig, err := os.ReadFile(catalogPath + ".sig")
	if err != nil {
		t.Fatalf("read signature: %v", err)
	}
	if err := catalogsig.Verify(data, sig, pub); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}

	if _, err := os.Stat(sigPath); err != nil {
		t.Fatalf("expected default signature path %s: %v", sigPath, err)
	}
}

func TestRun_SignWithEnvKeyProducesVerifiableArtifact(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "catalog-baseline.toml")
	data := []byte("[[entry]]\nexe_basename = \"git\"\n")
	if err := os.WriteFile(in, data, 0o644); err != nil {
		t.Fatalf("write catalog: %v", err)
	}
	pub, priv, err := catalogsig.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	t.Setenv("CATALOG_SIGNING_KEY", base64.StdEncoding.EncodeToString(priv))

	if err := run([]string{"sign", "--in", in}); err != nil {
		t.Fatalf("run sign: %v", err)
	}

	sig, err := os.ReadFile(in + ".sig")
	if err != nil {
		t.Fatalf("read signature: %v", err)
	}
	if err := catalogsig.Verify(data, sig, pub); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}

func TestRun_SignRejectsMissingKey(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "catalog-baseline.toml")
	if err := os.WriteFile(in, []byte("[[entry]]\nexe_basename = \"git\"\n"), 0o644); err != nil {
		t.Fatalf("write catalog: %v", err)
	}
	t.Setenv("CATALOG_SIGNING_KEY", "")
	if err := run([]string{"sign", "--in", in}); err == nil {
		t.Fatal("sign succeeded with no key; signing must not silently no-op")
	}
}

func TestRun_GenKeyRequiresPrivateKeyOutput(t *testing.T) {
	err := run([]string{"genkey"})
	if err == nil {
		t.Fatal("genkey without --key-out should fail instead of printing private material")
	}
	if !strings.Contains(err.Error(), "--key-out") {
		t.Fatalf("error should name --key-out: %v", err)
	}
}

func TestRun_GenKeyWritesPrivateKeyToFileAndDoesNotPrintIt(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "catalog-signing.key")
	var err error
	stdout := captureStdout(t, func() {
		err = run([]string{"genkey", "--key-out", keyPath})
	})
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read generated private key: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat generated private key: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("private key permissions = %o, want 0600", got)
	}
	encodedPrivate := strings.TrimSpace(string(raw))
	priv, err := base64.StdEncoding.DecodeString(encodedPrivate)
	if err != nil {
		t.Fatalf("generated private key is not base64: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("private key length = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	if strings.Contains(stdout, encodedPrivate) {
		t.Fatal("genkey printed the private signing key to stdout")
	}
	if !strings.Contains(stdout, "maintainerPubHex") {
		t.Fatalf("genkey output should tell maintainers which embedded public key to rotate:\n%s", stdout)
	}
}

func TestRun_UnknownSubcommand(t *testing.T) {
	if err := run([]string{"frobnicate"}); err == nil {
		t.Error("expected error for unknown subcommand")
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("close stdout pipe: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout pipe: %v", err)
	}
	return string(out)
}
