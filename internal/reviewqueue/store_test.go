package reviewqueue

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/byliu-labs/egress-guard/internal/catalog"
	"github.com/byliu-labs/egress-guard/internal/telemetry"
)

func TestOpen_MissingFileStartsEmptyQueue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.jsonl")
	q, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer q.Close()
	if len(q.Candidates()) != 0 {
		t.Fatalf("Candidates() = %v, want empty for a fresh queue", q.Candidates())
	}
}

func TestOpen_ReplaysIngestedReportsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.jsonl")
	q, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	report := telemetry.NewReport("uuid-1", catalog.Identity{ExeBasename: "curl"}, "api.example.com", "allow")
	if err := q.Ingest(report); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if err := q.Ingest(report); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer reopened.Close()
	cands := reopened.Candidates()
	if len(cands) != 1 || cands[0].Count != 2 {
		t.Fatalf("Candidates() after reopen = %+v, want one candidate with Count=2", cands)
	}
}

func TestOpen_ReplayDoesNotDuplicateOnDiskRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.jsonl")
	q, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	report := telemetry.NewReport("uuid-1", catalog.Identity{ExeBasename: "curl"}, "api.example.com", "allow")
	if err := q.Ingest(report); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	q.Close()

	for i := 0; i < 2; i++ {
		reopened, err := Open(path)
		if err != nil {
			t.Fatalf("re-Open #%d: %v", i, err)
		}
		if got := reopened.Candidates()[0].Count; got != 1 {
			t.Fatalf("re-Open #%d: Count = %d, want 1", i, got)
		}
		reopened.Close()
	}
}

func TestOpen_SkipsCorruptRecordsAndKeepsPriorCandidates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.jsonl")
	q, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	report := telemetry.NewReport("uuid-1", catalog.Identity{ExeBasename: "curl"}, "api.example.com", "allow")
	if err := q.Ingest(report); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := f.WriteString("{not-json\n"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close corrupt append: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer reopened.Close()
	if got := reopened.CorruptRecords(); got != 1 {
		t.Fatalf("CorruptRecords() = %d, want 1", got)
	}
	cands := reopened.Candidates()
	if len(cands) != 1 || cands[0].Key.Host != "api.example.com" || cands[0].Count != 1 {
		t.Fatalf("Candidates() after corrupt line = %+v, want prior valid candidate", cands)
	}
}
