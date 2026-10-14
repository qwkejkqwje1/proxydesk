package lock

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

var ErrInstanceAlreadyRunning = errors.New("another ProxyDesk instance is already running with this data directory")

type InstanceMetadata struct {
	PID       int       `json:"pid"`
	APIURL    string    `json:"api_url"`
	StartedAt time.Time `json:"started_at"`
}

type InstanceLock struct {
	lockPath string
	Meta     InstanceMetadata
}

// Acquire attempts to acquire the single-instance lock in dataDir.
// If another live instance holds the lock and responds on its loopback health endpoint,
// Acquire returns ErrInstanceAlreadyRunning along with the existing instance's metadata
// without killing any process or forcefully freeing ports.
func Acquire(dataDir string, apiListenAddr string) (*InstanceLock, *InstanceMetadata, error) {
	lockPath := filepath.Join(dataDir, "instance.lock")
	if raw, err := os.ReadFile(lockPath); err == nil {
		var existing InstanceMetadata
		if json.Unmarshal(raw, &existing) == nil && existing.APIURL != "" {
			if isInstanceReachable(existing.APIURL) {
				return nil, &existing, fmt.Errorf("%w at %s (PID %d)", ErrInstanceAlreadyRunning, existing.APIURL, existing.PID)
			}
		}
		// Stale lock file from crashed process; safe to remove after verifying health endpoint is down.
		_ = os.Remove(lockPath)
	}

	meta := InstanceMetadata{
		PID:       os.Getpid(),
		APIURL:    "http://" + apiListenAddr,
		StartedAt: time.Now().UTC(),
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("create instance lock: %w", err)
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(lockPath)
		return nil, nil, fmt.Errorf("write instance lock: %v / %v", writeErr, closeErr)
	}
	return &InstanceLock{lockPath: lockPath, Meta: meta}, nil, nil
}

func (l *InstanceLock) Release() error {
	if l == nil || l.lockPath == "" {
		return nil
	}
	return os.Remove(l.lockPath)
}

func isInstanceReachable(apiURL string) bool {
	client := &http.Client{Timeout: 400 * time.Millisecond}
	resp, err := client.Get(apiURL + "/api/v1/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
