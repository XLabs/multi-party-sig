package pool

import (
	"io"
	"runtime"
	"sync"
	"sync/atomic"
)

// searchAlone runs f, which may return nil, until count elements are found
func searchAlone(f func() interface{}, count int) []interface{} {
	results := make([]interface{}, count)
	for i := 0; i < len(results); i++ {
		results[i] = nil
		for ; results[i] == nil; results[i] = f() {
		}
	}
	return results
}

// parallelizeAlone calculates the result of f count times
func parallelizeAlone(f func(int) interface{}, count int) []interface{} {
	results := make([]interface{}, count)
	for i := 0; i < len(results); i++ {
		results[i] = f(i)
	}
	return results
}

// command is used to trigger our latent workers to do something.
//
// The idea is that a worker is told to either calculate a function once,
// or keep calculating a function until it returns a non nil result.
type command struct {
	search bool
	// This counter indicates the number of results that still need to be produced.
	// also used to store results in search mode.
	ctr *atomic.Int64

	// notifies when task is complete by each worker
	dn *sync.WaitGroup

	// This is the index/order we evaluate our function at, when not searching.
	i int

	f func(int) interface{}

	// the array where we put results
	results []interface{}
}

// workerSearch is the subroutine called when doing a search command.
//
// We need to keep searching for successful queries of f while *ctr > 0.
// When we find a successful result, we decrement *ctr.
func (c *command) workerSearch() {
	defer c.dn.Done()

	// keep searching while we still need results
	for c.ctr.Load() > 0 {
		// using 0 as dummy values, since search functions don't use the index
		res := c.f(0)
		if res == nil {
			continue
		}

		// store result using an atomic decrement, to avoid races on slice entry.
		if i := c.ctr.Add(-1); i >= 0 {
			c.results[i] = res
		}
	}
}

// worker starts up a new worker, listening to commands, and producing results
func worker(commands <-chan command) {
	for c := range commands {
		if c.search {
			c.workerSearch()
		} else {
			c.results[c.i] = c.f(c.i)
			c.ctr.Add(-1)
			c.dn.Done()
		}
	}
}

// Pool represents a pool of workers, used for parallelizing functions.
//
// Functions needing a *Pool will work with a nil receiver, doing the equivalent
// work on the current thread instead.
//
// By creating a pool, you avoid the overhead of spinning up goroutines for
// each new operation.
//
// A Pool is only ever intended to be used from a single goroutine, and might cause deadlocks
// if used by multiple goroutines concurrently.
type Pool struct {
	// The common channel used to send commands to the workers.
	//
	// This effectively makes a work stealing pool.
	commands chan command
	// This holds the number of workers we've created
	workerCount int
}

// NewPool creates a new pool, with a certain number of workers.
//
// If count ⩽ 0, this will use the number of available CPUs instead.
func NewPool(count int) *Pool {
	var p Pool

	if count <= 0 {
		count = runtime.NumCPU()
	}

	p.commands = make(chan command)
	p.workerCount = count

	for i := 0; i < count; i++ {
		go worker(p.commands)
	}

	return &p
}

// TearDown cleanly tears down a pool, closing channels, etc.
func (p *Pool) TearDown() {
	if p != nil {
		close(p.commands)
	}
}

// Search queries the function f, until count successes are found.
//
// f is supposed to try a single candidate, returning nil if that candidate isn't
// successful.
//
// The result will be an array containing the first count successes.
func (p *Pool) Search(count int, f func() interface{}) []interface{} {
	if p == nil {
		return searchAlone(f, count)
	}

	ctr := &atomic.Int64{}
	ctr.Store(int64(count))

	dn := &sync.WaitGroup{}
	dn.Add(p.workerCount)

	cmd := command{
		search:  true,
		ctr:     ctr,
		f:       func(i int) interface{} { return f() },
		results: make([]interface{}, count),
		dn:      dn,
	}

	for range p.workerCount {
		p.commands <- cmd
	}

	cmd.dn.Wait()

	return cmd.results
}

// Parallelize calls a function count times, passing in indices from 0..count-1.
//
// The result will be a slice containing [f(0), f(1), ..., f(count - 1)].
func (p *Pool) Parallelize(count int, f func(int) interface{}) []interface{} {
	if p == nil {
		return parallelizeAlone(f, count)
	}

	results := make([]interface{}, count)

	ctr := &atomic.Int64{}
	ctr.Store(int64(count))

	dn := &sync.WaitGroup{}
	dn.Add(count)
	for cmdI := range count {
		p.commands <- command{
			search:  false,
			i:       cmdI,
			ctr:     ctr,
			f:       f,
			results: results,
			dn:      dn,
		}
	}

	dn.Wait()

	return results
}

// LockedReader wraps an io.Reader to be safe for concurrent reads.
//
// This type implements io.Reader, returning the same output.
//
// This means acquiring a lock whenever a read happens, so be aware of that
// for performance or concurrency reasons.
type LockedReader struct {
	reader io.Reader
	m      sync.Mutex
}

// NewLockedReader creates a LockedReader by wrapping an underlying value.
func NewLockedReader(r io.Reader) *LockedReader {
	// Intentionally not initializing m, since the zero value is ok
	return &LockedReader{reader: r}
}

// Read implements io.Reader for LockedReader
//
// The behavior is to return the same output as the underlying reader. The difference
// is that it's safe to call this function concurrently.
//
// Naturally, when calling this function concurrently, what value ends up getting
// read is raced, but you won't end up reading the same value twice, or otherwise
// messing up the state of the reader.
func (r *LockedReader) Read(p []byte) (int, error) {
	r.m.Lock()
	defer r.m.Unlock()
	return r.reader.Read(p)
}
