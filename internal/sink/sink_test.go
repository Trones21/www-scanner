package sink

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/trones/www-scanner/internal/record"
)

func TestMmapWriteReadReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.bin")

	s, err := Create(path, 10)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	want := record.Record{
		Status: record.StatusComplete,
		WWW:    record.Side{Resolve: record.ResolveOK, TLS: record.TLSOK, HTTP: 200},
	}
	if err := s.Write(7, want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The file is the checkpoint, so it has to survive the process.
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer reopened.Close()

	if reopened.Len() != 10 {
		t.Errorf("Len() = %d, want 10", reopened.Len())
	}
	if got := reopened.Get(7); got != want {
		t.Errorf("Get(7) = %+v, want %+v", got, want)
	}
	// Everything else must still read as unattempted, which is what resume
	// keys off.
	for i := range 10 {
		if i == 7 {
			continue
		}
		if got := reopened.Get(i); got.Status != record.StatusUnattempted {
			t.Errorf("Get(%d).Status = %v, want StatusUnattempted", i, got.Status)
		}
	}
}

// The whole no-write-coordination claim rests on this: many workers writing at
// disjoint offsets with no lock must not corrupt each other.
func TestMmapConcurrentDisjointWrites(t *testing.T) {
	const n = 2000
	path := filepath.Join(t.TempDir(), "results.bin")

	s, err := Create(path, n)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer s.Close()

	var wg sync.WaitGroup
	for w := range 50 {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < n; i += 50 {
				s.Write(i, record.Record{
					Status:    record.StatusComplete,
					DurationM: uint16(i % 65535),
					WWW:       record.Side{HTTP: uint16(200 + i%100)},
				})
			}
		}(w)
	}
	wg.Wait()

	for i := range n {
		got := s.Get(i)
		if got.Status != record.StatusComplete {
			t.Fatalf("record %d was not written", i)
		}
		if want := uint16(i % 65535); got.DurationM != want {
			t.Fatalf("record %d has DurationM %d, want %d — writes overlapped", i, got.DurationM, want)
		}
		if want := uint16(200 + i%100); got.WWW.HTTP != want {
			t.Fatalf("record %d has HTTP %d, want %d — writes overlapped", i, got.WWW.HTTP, want)
		}
	}
}

// Positional records are meaningless against a different corpus, so reopening
// with a mismatched count must fail loudly rather than reinterpret them.
func TestCreateRefusesMismatchedCorpus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.bin")

	s, err := Create(path, 100)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	s.Close()

	if _, err := Create(path, 200); err == nil {
		t.Fatal("Create accepted a result file sized for a different corpus")
	}
}

func TestWriteOutOfRange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.bin")
	s, err := Create(path, 4)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer s.Close()

	if err := s.Write(4, record.Record{}); err == nil {
		t.Error("Write(4) into a 4-record file did not error")
	}
	if err := s.Write(-1, record.Record{}); err == nil {
		t.Error("Write(-1) did not error")
	}
}

func TestNullSinkDiscards(t *testing.T) {
	s := NewNull(100)
	if err := s.Write(5, record.Record{Status: record.StatusComplete}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := s.Get(5); got.Status != record.StatusUnattempted {
		t.Error("the null sink stored a record; a throughput run would be measuring storage")
	}
	if s.Len() != 100 {
		t.Errorf("Len() = %d, want 100", s.Len())
	}
}
