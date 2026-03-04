package admin

import (
	"os"
	"strings"
)

func isLikelyContainerRuntime() bool {
	// Allow explicit marking via env var (useful for custom container runtimes/tests).
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("VIBEGUARD_CONTAINER"))); v != "" {
		switch v {
		case "1", "true", "yes", "y", "on":
			return true
		case "0", "false", "no", "n", "off":
			return false
		}
	}

	// Docker typically injects this file.
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// Common on Linux containers: /proc/1/cgroup contains keywords like docker/kubepods/containerd.
	// Other platforms just return false.
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := strings.ToLower(string(b))
		if strings.Contains(s, "docker") ||
			strings.Contains(s, "kubepods") ||
			strings.Contains(s, "containerd") ||
			strings.Contains(s, "podman") {
			return true
		}
	}

	return false
}
