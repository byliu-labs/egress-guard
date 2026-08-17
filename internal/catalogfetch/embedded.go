package catalogfetch

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

const maintainerPubHex = "eb5f430ad2984b8d7e264be08443eed9b8d6dbd36768c862e0ea5b05af905ac4"

// MaintainerKey returns the public key pinned into this binary for the
// maintainer-published baseline catalog.
func MaintainerKey() ([]byte, error) {
	pub, err := hex.DecodeString(maintainerPubHex)
	if err != nil {
		return nil, fmt.Errorf("catalogfetch: decode embedded maintainer key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("catalogfetch: embedded maintainer key is %d bytes, want %d",
			len(pub), ed25519.PublicKeySize)
	}
	return pub, nil
}
