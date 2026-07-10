//go:build !darwin

package procid

func defaultLookup() Lookup { return unsupported{} }
