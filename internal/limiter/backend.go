package limiter

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/tidwall/buntdb"
)

type BackendService struct {
	db       *buntdb.DB
	dbWorker *Worker
}

type Worker struct {
	Stopped         bool
	ShutdownChannel chan string
	Interval        time.Duration
	period          time.Duration
	db              *buntdb.DB
}

func NewBackendWorker(interval time.Duration, db *buntdb.DB) *Worker {
	return &Worker{
		Stopped:         false,
		ShutdownChannel: make(chan string),
		Interval:        interval,
		period:          interval,
		db:              db,
	}
}
func (w *Worker) Run() {
	for {
		select {
		case <-w.ShutdownChannel:
			w.ShutdownChannel <- "stop"
			return
		case <-time.After(w.period):
			break
		}
		started := time.Now()
		w.db.Shrink()
		finished := time.Now()

		duration := finished.Sub(started)
		w.period = w.Interval - duration
	}
}

// Shutdown is a graceful shutdown mechanism
func (w *Worker) Shutdown() {
	w.Stopped = true

	w.ShutdownChannel <- "stop"
	<-w.ShutdownChannel

	close(w.ShutdownChannel)
}

func (be *BackendService) StartBackend(path string) error {
	var err error
	be.db, err = buntdb.Open(path)
	if err != nil {
		return err
	}
	// setup background worker
	be.dbWorker = NewBackendWorker(5*time.Minute, be.db)
	be.dbWorker.Run()
	defer be.CloseBackend()
	return nil
}

func (be *BackendService) CloseBackend() {
	be.db.Close()
}

type Number interface {
	RequestCounters
}

func (be *BackendService) Get(key string) (RequestCounters, error) {
	rq := &RequestCounters{}
	be.db.View(func(tx *buntdb.Tx) error {
		val, err := tx.Get(key)
		if err != nil {
			if err == buntdb.ErrNotFound {
				rq.BucketStart = time.Now()
				return nil
			}
			return err
		}

		json.Unmarshal([]byte(val), rq)
		return nil
	})
	return *rq, nil
}

func (be *BackendService) Update(key string, counters RequestCounters) error {
	err := be.db.Update(func(tx *buntdb.Tx) error {
		b, _ := json.Marshal(counters)
		// need to calculate when to auto expire this value, everytime the value is set, the TTL gets reset
		// we want the TTL to be the lifetime of the bucket, not the time since last update
		ttlRemaining := expireTime - time.Since(counters.BucketStart)
		_, _, err := tx.Set(key, string(b), &buntdb.SetOptions{Expires: true, TTL: ttlRemaining})
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

func (be *BackendService) BatchUpdate(keys []string, values []RequestCounters) error {
	if len(keys) != len(values) {
		return fmt.Errorf("len(keys) != len(values). Expected %d but got %d values", len(keys), len(values))
	}

	err := be.db.Update(func(tx *buntdb.Tx) error {
		for i := range keys {
			b, _ := json.Marshal(values[i])

			// need to calculate when to auto expire this value, everytime the value is set, the TTL gets reset
			// we want the TTL to be the lifetime of the bucket, not the time since last update
			ttlRemaining := expireTime - time.Since(values[i].BucketStart)
			_, _, err := tx.Set(keys[i], string(b), &buntdb.SetOptions{Expires: true, TTL: ttlRemaining})

			if err != nil {
				return err
			}
		}
		return nil
	})
	return err
}
