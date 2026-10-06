//go:build !darwin

package cli

func reviewLogPath() (string, error) { return BlockLogPath() }
