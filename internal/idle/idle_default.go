//go:build !darwin

package idle

// NewSystemProbe returns an unsupported probe outside macOS.
func NewSystemProbe() Probe { return unsupportedProbe{} }

type unsupportedProbe struct{}

func (unsupportedProbe) SecondsSinceInput() (float64, error) { return 0, ErrUnsupported }
