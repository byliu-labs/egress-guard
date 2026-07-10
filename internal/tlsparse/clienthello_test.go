package tlsparse

import (
	"errors"
	"testing"
)

func TestParseSNI_HappyPath(t *testing.T) {
	helo := buildClientHello("example.com")
	got, err := ParseSNI(helo)
	if err != nil {
		t.Fatalf("ParseSNI returned error: %v", err)
	}
	if got != "example.com" {
		t.Fatalf("ParseSNI = %q, want example.com", got)
	}
}

func TestParseSNI_NoSNIExtension(t *testing.T) {
	helo := buildClientHelloNoSNI()
	_, err := ParseSNI(helo)
	if !errors.Is(err, ErrNoSNI) {
		t.Fatalf("ParseSNI on no-SNI handshake = %v, want ErrNoSNI", err)
	}
}

func TestParseSNI_NotTLS(t *testing.T) {
	notTLS := []byte{0xff, 0xff, 0xff, 0xff, 0xff}
	_, err := ParseSNI(notTLS)
	if !errors.Is(err, ErrNotTLS) {
		t.Fatalf("ParseSNI on non-TLS bytes = %v, want ErrNotTLS", err)
	}
}

func TestParseSNI_Truncated(t *testing.T) {
	full := buildClientHello("example.com")
	_, err := ParseSNI(full[:10])
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("ParseSNI on truncated = %v, want ErrTruncated", err)
	}
}

func TestParseSNI_Oversize(t *testing.T) {
	huge := make([]byte, 65536)
	copy(huge, []byte{0x16, 0x03, 0x01, 0xff, 0xff})
	_, err := ParseSNI(huge)
	if !errors.Is(err, ErrOversize) {
		t.Fatalf("ParseSNI on oversize = %v, want ErrOversize", err)
	}
}

// buildClientHello constructs a minimally valid TLS ClientHello with the
// given SNI for testing.
func buildClientHello(sni string) []byte {
	return buildClientHelloHelper(sni, true)
}

func buildClientHelloNoSNI() []byte {
	return buildClientHelloHelper("", false)
}
