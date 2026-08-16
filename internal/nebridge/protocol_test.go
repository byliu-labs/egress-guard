package nebridge

import (
	"bytes"
	"encoding/binary"
	"net"
	"reflect"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/tlsparse"
)

func TestRequest_RoundTrip(t *testing.T) {
	clientHello := testClientHello()
	if host, err := tlsparse.ParseSNI(clientHello); err != nil || host != "example.com" {
		t.Fatalf("test ClientHello is invalid: host=%q err=%v", host, err)
	}

	request := Request{
		DstIP:       net.IPv4(203, 0, 113, 10),
		DstPort:     443,
		AuditToken:  [32]byte{1, 2, 3, 4},
		ClientHello: clientHello,
	}

	var encoded bytes.Buffer
	if err := EncodeRequest(&encoded, request); err != nil {
		t.Fatalf("EncodeRequest returned error: %v", err)
	}

	got, err := DecodeRequest(&encoded)
	if err != nil {
		t.Fatalf("DecodeRequest returned error: %v", err)
	}
	if !reflect.DeepEqual(got, request) {
		t.Fatalf("request round trip = %#v, want %#v", got, request)
	}
}

func TestResponse_RoundTrip(t *testing.T) {
	response := Response{
		Verdict: VerdictDrop,
		Host:    "example.com",
		Reason:  "catalog miss",
	}

	var encoded bytes.Buffer
	if err := EncodeResponse(&encoded, response); err != nil {
		t.Fatalf("EncodeResponse returned error: %v", err)
	}

	got, err := DecodeResponse(&encoded)
	if err != nil {
		t.Fatalf("DecodeResponse returned error: %v", err)
	}
	if !reflect.DeepEqual(got, response) {
		t.Fatalf("response round trip = %#v, want %#v", got, response)
	}
}

func TestResponse_AskVerdictRoundTrip(t *testing.T) {
	response := Response{
		Verdict: VerdictAsk,
		Host:    "unknown.example",
		Reason:  "prompt_required",
	}

	var encoded bytes.Buffer
	if err := EncodeResponse(&encoded, response); err != nil {
		t.Fatalf("EncodeResponse returned error: %v", err)
	}

	got, err := DecodeResponse(&encoded)
	if err != nil {
		t.Fatalf("DecodeResponse returned error: %v", err)
	}
	if !reflect.DeepEqual(got, response) {
		t.Fatalf("response round trip = %#v, want %#v", got, response)
	}
}

func TestDecodeRequest_TruncatedHeader(t *testing.T) {
	_, err := DecodeRequest(bytes.NewReader([]byte{1, 0, 0}))
	if err == nil {
		t.Fatal("DecodeRequest accepted a truncated header")
	}
}

func TestDecodeRequest_OversizeClientHello(t *testing.T) {
	var frame bytes.Buffer
	frame.WriteByte(1)
	frame.Write(make([]byte, net.IPv6len))
	if err := binary.Write(&frame, binary.BigEndian, uint16(443)); err != nil {
		t.Fatalf("write destination port: %v", err)
	}
	frame.Write(make([]byte, 32))
	if err := binary.Write(&frame, binary.BigEndian, uint16(tlsparse.MaxClientHelloBytes+1)); err != nil {
		t.Fatalf("write ClientHello length: %v", err)
	}

	_, err := DecodeRequest(&frame)
	if err == nil {
		t.Fatal("DecodeRequest accepted an oversize ClientHello")
	}
}

func testClientHello() []byte {
	clientHello := []byte{
		0x16, 0x03, 0x01, 0x00, 0x43,
		0x01, 0x00, 0x00, 0x3f, 0x03, 0x03,
	}
	clientHello = append(clientHello, make([]byte, 32)...)
	clientHello = append(clientHello,
		0x00,
		0x00, 0x02, 0x13, 0x01,
		0x01, 0x00,
		0x00, 0x14,
		0x00, 0x00, 0x00, 0x10,
		0x00, 0x0e,
		0x00, 0x00, 0x0b,
	)
	return append(clientHello, "example.com"...)
}
