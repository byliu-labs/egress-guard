//go:build !darwin

package main

import "github.com/byliu-labs/egress-guard/internal/menubar"

func main() {
	menubar.Run()
}
