//go:build !darwin

package prompt

// DefaultPlatformNotifier returns the fallback notifier for unsupported platforms.
// Returns TimeoutNotifier which always times out and default-denies.
func DefaultPlatformNotifier() Notifier {
	return TimeoutNotifier{}
}
