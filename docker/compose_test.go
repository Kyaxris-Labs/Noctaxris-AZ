package docker_test

import (
	"os"
	"strings"
	"testing"
)

func TestComposeFileHasNoDockerSock(t *testing.T) {
	for _, name := range []string{
		"compose.yaml",
		"compose.engine.yaml",
		"compose.engine-privileged.yaml",
	} {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		content := string(b)
		if strings.Contains(content, "/var/run/docker.sock") {
			t.Fatalf("%s must not mount /var/run/docker.sock", name)
		}
		if hasDockerSockVolumeEntry(content) {
			t.Fatalf("%s must not bind or volume-mount docker.sock", name)
		}
	}
}

func TestComposeEngineWiresNestedTLS(t *testing.T) {
	b, err := os.ReadFile("compose.engine.yaml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(b)
	for _, want := range []string{
		"noctaxris-az-engine",
		"NOCTAXRIS_AZ_DOCKER_HOST",
		"tcp://noctaxris-az-engine:2376",
		"docker:27-dind@",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("compose.engine.yaml missing %q", want)
		}
	}
	if strings.Contains(content, "2375:2375") || strings.Contains(content, "2376:2376") {
		t.Fatal("compose.engine.yaml must not publish engine ports to the host")
	}
}

// hasDockerSockVolumeEntry reports a non-comment YAML volume list item that
// mounts a path ending in docker.sock or uses a docker.sock: host bind.
func hasDockerSockVolumeEntry(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if idx := strings.Index(trimmed, " #"); idx >= 0 {
			trimmed = strings.TrimSpace(trimmed[:idx])
		}
		if !strings.HasPrefix(trimmed, "-") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
		if strings.HasSuffix(rest, "docker.sock") || strings.Contains(rest, "docker.sock:") {
			return true
		}
	}
	return false
}
