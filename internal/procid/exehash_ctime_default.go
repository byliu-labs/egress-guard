//go:build !darwin && !linux

package procid

import "syscall"

func ctimeNanos(st *syscall.Stat_t) int64 { return 0 }
