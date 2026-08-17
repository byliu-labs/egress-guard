package daemon

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestSpliceBoth_ReturnsBytesEachDirection(t *testing.T) {
	clientSide, daemonClient := net.Pipe()
	daemonUpstream, upstreamSide := net.Pipe()

	errCh := make(chan error, 2)
	go func() {
		defer clientSide.Close()
		if _, err := clientSide.Write(bytes.Repeat([]byte("u"), 300)); err != nil {
			errCh <- err
			return
		}
		got, err := io.ReadAll(clientSide)
		if err != nil {
			errCh <- err
			return
		}
		if len(got) != 700 {
			t.Errorf("client read %d bytes, want 700", len(got))
		}
		errCh <- nil
	}()
	go func() {
		defer upstreamSide.Close()
		got := make([]byte, 300)
		if _, err := io.ReadFull(upstreamSide, got); err != nil {
			errCh <- err
			return
		}
		if _, err := upstreamSide.Write(bytes.Repeat([]byte("d"), 700)); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	up, down := spliceBoth(daemonClient, daemonUpstream)
	if up != 300 {
		t.Errorf("up = %d, want 300", up)
	}
	if down != 700 {
		t.Errorf("down = %d, want 700", down)
	}
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("pipe peer failed: %v", err)
		}
	}
}
