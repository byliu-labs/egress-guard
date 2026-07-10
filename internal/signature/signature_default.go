//go:build !darwin

package signature

func defaultVerifier() Verifier {
	return unsupported{}
}
