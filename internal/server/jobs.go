package server

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/Kumar-ranjan12345/magpie/internal/engine"
)

// A job is one scan running in the background, so the browser can show real
// progress instead of waiting on a single long request.
type job struct {
	mu      sync.Mutex
	name    string
	stage   engine.Stage
	done    bool
	err     string
	report  []byte
	started time.Time
	expires time.Time
}

type jobStatus struct {
	Name    string `json:"name"`
	Stage   string `json:"stage"`
	Done    bool   `json:"done"`
	Error   string `json:"error,omitempty"`
	Elapsed int64  `json:"elapsedMs"`
}

func (j *job) status() jobStatus {
	j.mu.Lock()
	defer j.mu.Unlock()
	return jobStatus{Name: j.name, Stage: string(j.stage), Done: j.done, Error: j.err, Elapsed: time.Since(j.started).Milliseconds()}
}

// Finished reports stay available this long, so a refresh of the report page works.
const jobTTL = 30 * time.Minute

type jobStore struct {
	mu   sync.Mutex
	jobs map[string]*job
}

func newJobStore() *jobStore { return &jobStore{jobs: map[string]*job{}} }

func (s *jobStore) add(name string) (string, *job) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	id := hex.EncodeToString(b)
	now := time.Now()
	j := &job{name: name, started: now, expires: now.Add(jobTTL)}

	s.mu.Lock()
	defer s.mu.Unlock()
	for k, old := range s.jobs {
		if now.After(old.expires) {
			delete(s.jobs, k)
		}
	}
	s.jobs[id] = j
	return id, j
}

func (s *jobStore) get(id string) *job {
	s.mu.Lock()
	defer s.mu.Unlock()
	j := s.jobs[id]
	if j != nil && time.Now().After(j.expires) {
		delete(s.jobs, id)
		return nil
	}
	return j
}
