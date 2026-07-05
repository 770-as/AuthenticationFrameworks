package network

import (
	"os"
	"strings"
)

// RequireCapturedMachineInfoFromEnv is true when REQUIRE_CAPTURED_MACHINE_INFO is
// set (recommended for Docker/production). Refuses goldenMachineInfo fallback.
func RequireCapturedMachineInfoFromEnv() bool {
	v := strings.TrimSpace(os.Getenv("REQUIRE_CAPTURED_MACHINE_INFO"))
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
