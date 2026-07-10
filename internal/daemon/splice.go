package daemon

import (
	"io"
	"net"
	"sync"
	"time"
)

// spliceBoth shuttles bytes in both directions between client and upstream
// until either side closes.
func spliceBoth(client, upstream net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(upstream, client); upstream.Close() }()
	go func() { defer wg.Done(); _, _ = io.Copy(client, upstream); client.Close() }()
	wg.Wait()
}

// time shims so tests can stub if needed.
func timeNow() time.Time  { return time.Now() }
func timeZero() time.Time { return time.Time{} }

const timeMillisecond = time.Millisecond

// itoa: smallest dependency-free integer-to-string for ports.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [6]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
