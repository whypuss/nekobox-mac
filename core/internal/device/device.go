package device

import (
	"runtime"
	"runtime/debug"
)

// ConfigureBackgroundRuntime tunes memory use for the VPN process.
func ConfigureBackgroundRuntime() {
	debug.SetMemoryLimit(192 << 20)
	debug.SetGCPercent(150)
}

func NumUDPWorkers() int {
	numUDPWorkers := 4
	if num := runtime.GOMAXPROCS(0); num > numUDPWorkers {
		numUDPWorkers = num
	}
	return numUDPWorkers
}
