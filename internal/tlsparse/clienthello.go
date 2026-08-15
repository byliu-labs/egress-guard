// Package tlsparse extracts the SNI hostname from a TLS ClientHello without
// performing any cryptographic operations. We never decrypt — we only read
// the cleartext SNI extension to make a routing decision.
package tlsparse

import (
	"encoding/binary"
	"errors"
)

// MaxClientHelloBytes bounds how much we read before deciding the handshake
// is malformed or an attempted DoS. Real ClientHellos are <2 KiB; the TLS
// record max is 16 KiB. We bound at 16 KiB.
const MaxClientHelloBytes = 16 * 1024

var (
	ErrNotTLS    = errors.New("tlsparse: not a TLS handshake")
	ErrTruncated = errors.New("tlsparse: ClientHello truncated")
	ErrOversize  = errors.New("tlsparse: ClientHello exceeds bound")
	ErrNoSNI     = errors.New("tlsparse: ClientHello has no SNI extension")
)

// ParseSNI extracts the server_name (host_name) from a TLS ClientHello.
// Input is the raw bytes a TLS server would receive on accept(). The function
// reads only what it needs to find the SNI; remaining bytes are ignored.
func ParseSNI(b []byte) (string, error) {
	if len(b) > MaxClientHelloBytes {
		return "", ErrOversize
	}
	// TLS Record Layer: type(1) | version(2) | length(2) | payload
	if len(b) < 5 {
		return "", ErrTruncated
	}
	if b[0] != 0x16 { // handshake
		return "", ErrNotTLS
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recLen+5 > len(b) {
		return "", ErrTruncated
	}
	hs := b[5 : 5+recLen]
	// Handshake: msg_type(1)=0x01 | length(3) | body
	if len(hs) < 4 || hs[0] != 0x01 {
		return "", ErrNotTLS
	}
	hsLen := (int(hs[1]) << 16) | (int(hs[2]) << 8) | int(hs[3])
	if hsLen+4 > len(hs) {
		return "", ErrTruncated
	}
	body := hs[4 : 4+hsLen]
	// ClientHello body: version(2) | random(32) | session_id
	if len(body) < 2+32+1 {
		return "", ErrTruncated
	}
	p := body[2+32:]
	// session_id
	if len(p) < 1 {
		return "", ErrTruncated
	}
	sidLen := int(p[0])
	if 1+sidLen > len(p) {
		return "", ErrTruncated
	}
	p = p[1+sidLen:]
	// cipher_suites
	if len(p) < 2 {
		return "", ErrTruncated
	}
	csLen := int(binary.BigEndian.Uint16(p[:2]))
	if 2+csLen > len(p) {
		return "", ErrTruncated
	}
	p = p[2+csLen:]
	// compression_methods
	if len(p) < 1 {
		return "", ErrTruncated
	}
	cmLen := int(p[0])
	if 1+cmLen > len(p) {
		return "", ErrTruncated
	}
	p = p[1+cmLen:]
	// extensions
	if len(p) < 2 {
		return "", ErrNoSNI
	}
	extLen := int(binary.BigEndian.Uint16(p[:2]))
	if 2+extLen > len(p) {
		return "", ErrTruncated
	}
	exts := p[2 : 2+extLen]
	for len(exts) >= 4 {
		extType := binary.BigEndian.Uint16(exts[:2])
		extDataLen := int(binary.BigEndian.Uint16(exts[2:4]))
		if 4+extDataLen > len(exts) {
			return "", ErrTruncated
		}
		extData := exts[4 : 4+extDataLen]
		if extType == 0x0000 { // server_name
			return parseSNIExtension(extData)
		}
		exts = exts[4+extDataLen:]
	}
	return "", ErrNoSNI
}

func parseSNIExtension(data []byte) (string, error) {
	if len(data) < 2 {
		return "", ErrTruncated
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	if 2+listLen > len(data) {
		return "", ErrTruncated
	}
	list := data[2 : 2+listLen]
	for len(list) >= 3 {
		nameType := list[0]
		nameLen := int(binary.BigEndian.Uint16(list[1:3]))
		if 3+nameLen > len(list) {
			return "", ErrTruncated
		}
		if nameType == 0x00 { // host_name
			return string(list[3 : 3+nameLen]), nil
		}
		list = list[3+nameLen:]
	}
	return "", ErrNoSNI
}

// BuildClientHelloForTest constructs a raw ClientHello fixture without
// depending on a real network capture.
func BuildClientHelloForTest(sni string, includeSNI bool) []byte {
	return buildClientHelloHelper(sni, includeSNI)
}

func buildClientHelloHelper(sni string, includeSNI bool) []byte {
	body := make([]byte, 0, 256)
	body = append(body, 0x03, 0x03)             // version TLS 1.2
	body = append(body, make([]byte, 32)...)    // random (zeroed for tests)
	body = append(body, 0x00)                   // session_id_len = 0
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites_len=2, TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00)             // compression_methods: none

	exts := make([]byte, 0, 64)
	if includeSNI && sni != "" {
		var sniExt []byte
		listLen := uint16(3 + len(sni))
		sniExt = append(sniExt, byte(listLen>>8), byte(listLen))
		sniExt = append(sniExt, 0x00) // host_name
		sniExt = append(sniExt, byte(len(sni)>>8), byte(len(sni)))
		sniExt = append(sniExt, []byte(sni)...)

		exts = append(exts, 0x00, 0x00)
		exts = append(exts, byte(len(sniExt)>>8), byte(len(sniExt)))
		exts = append(exts, sniExt...)
	}
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	rec = append(rec, hs...)
	return rec
}
