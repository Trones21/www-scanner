// Package sink is where results land.
//
// Two implementations, behind one interface, so the network ceiling and the
// storage ceiling can be measured independently. A throughput run uses Null
// and the storage path cannot contaminate the number; a census run uses Mmap
// and speed is not the point.
package sink

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/trones/www-scanner/internal/record"
)

// Sink accepts results by corpus index.
//
// Write must be safe for concurrent use from many workers. It is not a queue
// and there is no writer goroutine: index i owns bytes [i*Width, (i+1)*Width)
// and no two workers are ever handed the same index.
type Sink interface {
	Write(idx int, r record.Record) error
	// Get returns the record already stored at idx. Resume reads this to
	// find where a previous run stopped.
	Get(idx int) record.Record
	Len() int
	Sync() error
	Close() error
}

// Null discards everything. The point of the throughput run.
type Null struct{ n int }

// NewNull returns a sink sized for n records that stores none of them.
func NewNull(n int) *Null { return &Null{n: n} }

func (s *Null) Write(int, record.Record) error { return nil }
func (s *Null) Get(int) record.Record          { return record.Record{} }
func (s *Null) Len() int                       { return s.n }
func (s *Null) Sync() error                    { return nil }
func (s *Null) Close() error                   { return nil }

// Mmap is a fixed-width result file mapped into memory.
//
// Workers write straight into the mapping at disjoint offsets, so a completed
// record costs a few stores and no syscall. At a billion domains the syscall
// per record that WriteAt would cost is the difference between the storage
// path being free and being the bottleneck.
type Mmap struct {
	f    *os.File
	data []byte
	n    int
}

// Create makes (or reopens) a result file sized for n records.
//
// Reopening is how resume works: the file is its own checkpoint, because
// StatusUnattempted is the zero value and a sparse file reads as zeroes.
func Create(path string, n int) (*Mmap, error) {
	if n <= 0 {
		return nil, fmt.Errorf("result file needs a positive record count, got %d", n)
	}
	size := int64(n) * record.Width

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open result file: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat result file: %w", err)
	}
	if info.Size() != size {
		if info.Size() != 0 {
			// A mismatch means this file was written against a different
			// corpus. Positional records are meaningless across corpora,
			// so refuse rather than silently reinterpret them.
			f.Close()
			return nil, fmt.Errorf(
				"result file %s holds %d records but corpus has %d; positional records are not portable across corpora",
				path, info.Size()/record.Width, n)
		}
		if err := f.Truncate(size); err != nil {
			f.Close()
			return nil, fmt.Errorf("size result file: %w", err)
		}
	}

	data, err := unix.Mmap(int(f.Fd()), 0, int(size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("mmap result file: %w", err)
	}
	// Feeding workers in corpus order keeps completions roughly sequential,
	// so tell the kernel that is the access pattern.
	_ = unix.Madvise(data, unix.MADV_SEQUENTIAL)

	return &Mmap{f: f, data: data, n: n}, nil
}

// Open maps an existing result file read-write without resizing it.
func Open(path string) (*Mmap, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open result file: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat result file: %w", err)
	}
	if info.Size()%record.Width != 0 {
		f.Close()
		return nil, fmt.Errorf("result file %s is %d bytes, not a multiple of the %d-byte record", path, info.Size(), record.Width)
	}
	data, err := unix.Mmap(int(f.Fd()), 0, int(info.Size()), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("mmap result file: %w", err)
	}
	return &Mmap{f: f, data: data, n: int(info.Size() / record.Width)}, nil
}

// Write stores r at idx. Safe from any number of goroutines as long as each
// index is written by exactly one of them.
func (s *Mmap) Write(idx int, r record.Record) error {
	if idx < 0 || idx >= s.n {
		return fmt.Errorf("index %d out of range for %d records", idx, s.n)
	}
	off := idx * record.Width
	r.Encode(s.data[off : off+record.Width])
	return nil
}

// Get reads the record at idx.
func (s *Mmap) Get(idx int) record.Record {
	if idx < 0 || idx >= s.n {
		return record.Record{}
	}
	off := idx * record.Width
	return record.Decode(s.data[off : off+record.Width])
}

func (s *Mmap) Len() int { return s.n }

// Sync flushes dirty pages so an interrupted run resumes from real data
// rather than from whatever the page cache had got round to.
func (s *Mmap) Sync() error {
	if s.data == nil {
		return nil
	}
	return unix.Msync(s.data, unix.MS_SYNC)
}

// Close flushes and unmaps.
func (s *Mmap) Close() error {
	if s.data == nil {
		return s.f.Close()
	}
	syncErr := unix.Msync(s.data, unix.MS_SYNC)
	unmapErr := unix.Munmap(s.data)
	s.data = nil
	closeErr := s.f.Close()
	for _, err := range []error{syncErr, unmapErr, closeErr} {
		if err != nil {
			return err
		}
	}
	return nil
}
