// Package nebridge defines the wire protocol between the NEFilter provider
// and the privileged egress-guard daemon. It carries raw TLS ClientHello bytes
// only; TLS is never decrypted.
package nebridge

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/byliu-labs/egress-guard/internal/tlsparse"
)

const (
	protocolVersion   = 1
	requestHeaderLen  = 1 + net.IPv6len + 2 + 32 + 2
	responseHeaderLen = 1 + 1 + 2
	maxUint16         = int(^uint16(0))
)

// Request is a TLS ClientHello observation from the NEFilter provider.
type Request struct {
	DstIP       net.IP
	DstPort     int
	AuditToken  [32]byte
	ClientHello []byte
}

// Verdict is the bridge response's connection decision.
type Verdict uint8

const (
	VerdictDrop  Verdict = 0
	VerdictAllow Verdict = 1
)

// Response is the daemon's decision for a bridge request.
type Response struct {
	Verdict Verdict
	Host    string
	Reason  string
}

// EncodeRequest writes a versioned, big-endian request frame.
func EncodeRequest(w io.Writer, request Request) error {
	dstIP := request.DstIP.To16()
	if dstIP == nil {
		return fmt.Errorf("nebridge: request destination IP is invalid: %q", request.DstIP)
	}
	if request.DstPort < 0 || request.DstPort > maxUint16 {
		return fmt.Errorf("nebridge: request destination port %d is outside uint16 range", request.DstPort)
	}
	if len(request.ClientHello) > tlsparse.MaxClientHelloBytes {
		return fmt.Errorf("nebridge: request ClientHello is %d bytes, maximum is %d", len(request.ClientHello), tlsparse.MaxClientHelloBytes)
	}

	var header [requestHeaderLen]byte
	header[0] = protocolVersion
	copy(header[1:], dstIP)
	binary.BigEndian.PutUint16(header[1+net.IPv6len:], uint16(request.DstPort))
	copy(header[1+net.IPv6len+2:], request.AuditToken[:])
	binary.BigEndian.PutUint16(header[requestHeaderLen-2:], uint16(len(request.ClientHello)))

	if err := writeAll(w, header[:]); err != nil {
		return fmt.Errorf("nebridge: write request header: %w", err)
	}
	if err := writeAll(w, request.ClientHello); err != nil {
		return fmt.Errorf("nebridge: write request ClientHello: %w", err)
	}
	return nil
}

// DecodeRequest reads and validates one versioned, big-endian request frame.
func DecodeRequest(r io.Reader) (Request, error) {
	var header [requestHeaderLen]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Request{}, fmt.Errorf("nebridge: read request header: %w", err)
	}
	if header[0] != protocolVersion {
		return Request{}, fmt.Errorf("nebridge: unsupported request version %d", header[0])
	}

	clientHelloLen := int(binary.BigEndian.Uint16(header[requestHeaderLen-2:]))
	if clientHelloLen > tlsparse.MaxClientHelloBytes {
		return Request{}, fmt.Errorf("nebridge: request ClientHello is %d bytes, maximum is %d", clientHelloLen, tlsparse.MaxClientHelloBytes)
	}
	clientHello := make([]byte, clientHelloLen)
	if _, err := io.ReadFull(r, clientHello); err != nil {
		return Request{}, fmt.Errorf("nebridge: read request ClientHello: %w", err)
	}

	var auditToken [32]byte
	copy(auditToken[:], header[1+net.IPv6len+2:requestHeaderLen-2])
	return Request{
		DstIP:       net.IP(append([]byte(nil), header[1:1+net.IPv6len]...)).To16(),
		DstPort:     int(binary.BigEndian.Uint16(header[1+net.IPv6len:])),
		AuditToken:  auditToken,
		ClientHello: clientHello,
	}, nil
}

// EncodeResponse writes a versioned, big-endian response frame.
func EncodeResponse(w io.Writer, response Response) error {
	if !response.Verdict.valid() {
		return fmt.Errorf("nebridge: invalid response verdict %d", response.Verdict)
	}
	if len(response.Host) > maxUint16 {
		return fmt.Errorf("nebridge: response host is %d bytes, maximum is %d", len(response.Host), maxUint16)
	}
	if len(response.Reason) > maxUint16 {
		return fmt.Errorf("nebridge: response reason is %d bytes, maximum is %d", len(response.Reason), maxUint16)
	}

	var header [responseHeaderLen]byte
	header[0] = protocolVersion
	header[1] = byte(response.Verdict)
	binary.BigEndian.PutUint16(header[2:], uint16(len(response.Host)))
	if err := writeAll(w, header[:]); err != nil {
		return fmt.Errorf("nebridge: write response header: %w", err)
	}
	if err := writeAll(w, []byte(response.Host)); err != nil {
		return fmt.Errorf("nebridge: write response host: %w", err)
	}

	binary.BigEndian.PutUint16(header[0:2], uint16(len(response.Reason)))
	if err := writeAll(w, header[:2]); err != nil {
		return fmt.Errorf("nebridge: write response reason length: %w", err)
	}
	if err := writeAll(w, []byte(response.Reason)); err != nil {
		return fmt.Errorf("nebridge: write response reason: %w", err)
	}
	return nil
}

// DecodeResponse reads and validates one versioned, big-endian response frame.
func DecodeResponse(r io.Reader) (Response, error) {
	var header [responseHeaderLen]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Response{}, fmt.Errorf("nebridge: read response header: %w", err)
	}
	if header[0] != protocolVersion {
		return Response{}, fmt.Errorf("nebridge: unsupported response version %d", header[0])
	}

	verdict := Verdict(header[1])
	if !verdict.valid() {
		return Response{}, fmt.Errorf("nebridge: invalid response verdict %d", verdict)
	}
	host, err := readString(r, int(binary.BigEndian.Uint16(header[2:])), "host")
	if err != nil {
		return Response{}, err
	}

	var reasonLen [2]byte
	if _, err := io.ReadFull(r, reasonLen[:]); err != nil {
		return Response{}, fmt.Errorf("nebridge: read response reason length: %w", err)
	}
	reason, err := readString(r, int(binary.BigEndian.Uint16(reasonLen[:])), "reason")
	if err != nil {
		return Response{}, err
	}
	return Response{Verdict: verdict, Host: host, Reason: reason}, nil
}

func (v Verdict) valid() bool {
	return v == VerdictAllow || v == VerdictDrop
}

func writeAll(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func readString(r io.Reader, length int, field string) (string, error) {
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return "", fmt.Errorf("nebridge: read response %s: %w", field, err)
	}
	return string(data), nil
}
