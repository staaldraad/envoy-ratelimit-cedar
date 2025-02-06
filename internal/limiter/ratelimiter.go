package limiter

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	pb "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/golang-jwt/jwt"
	"github.com/tidwall/buntdb"
)

const expireTime = time.Second * 10

type RateLimitServer struct {
	HMACSecret []byte
	db         *buntdb.DB
	dbWorker   *Worker
}

type Worker struct {
	Stopped         bool
	ShutdownChannel chan string
	Interval        time.Duration
	period          time.Duration
	db              *buntdb.DB
}

type RequestState struct {
	RawPath       string
	Path          PathParts
	RemoteAddress string
	Authorization jwt.MapClaims
	Method        string
}

type RequestCounters struct {
	BucketStart time.Time                        // when did this request counter first start
	Global      int64                            // total requests
	Table       map[string]*TableRequestCounters // requests by path
	Function    map[string]int                   // requests for function
}

type TableRequestCounters struct {
	MethodCount map[string]int
}

func NewWorker(interval time.Duration, db *buntdb.DB) *Worker {
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

func (rl *RateLimitServer) StartBackend(path string) error {
	var err error
	rl.db, err = buntdb.Open(path)
	if err != nil {
		return err
	}
	// setup background worker
	rl.dbWorker = NewWorker(5*time.Minute, rl.db)
	rl.dbWorker.Run()
	defer rl.CloseBackend()
	return nil
}

func (rl *RateLimitServer) CloseBackend() {
	rl.db.Close()
}

func (rl *RateLimitServer) DbManagerStart() {

}

func (rl *RateLimitServer) ShouldRateLimit(ctx context.Context, request *pb.RateLimitRequest) (*pb.RateLimitResponse, error) {
	fmt.Printf("limiter called %v\n", request)

	state := &RequestState{}
	preferHeader := ""
	// get values from descriptors
	for i := 0; i < len(request.Descriptors); i++ {
		for j := 0; j < len(request.Descriptors[i].Entries); j++ {
			switch request.Descriptors[i].Entries[j].Key {
			case "path":
				state.RawPath = request.Descriptors[i].Entries[j].Value
				state.Path = parsePath(state.RawPath)
			case "remote_address":
				state.RemoteAddress = request.Descriptors[i].Entries[j].Value
			case "authorization":
				state.Authorization = extractJWT(rl.HMACSecret, request.Descriptors[i].Entries[j].Value)
			case "method":
				state.Method = request.Descriptors[i].Entries[j].Value
			case "prefer":
				preferHeader = request.Descriptors[i].Entries[j].Value
			}
		}
	}
	// update method to SQL method
	// need to do this here because we first needed to extract the prefer header from the descriptors
	if state.Method != "" {
		state.Method = extractSQLMethod(state.Method, preferHeader)
	}

	fmt.Println(state)

	remoteAddressRequestCounters := &RequestCounters{}
	// get IP limits
	rl.db.View(func(tx *buntdb.Tx) error {
		val, err := tx.Get(state.RemoteAddress)
		if err != nil {
			if err == buntdb.ErrNotFound {
				remoteAddressRequestCounters.BucketStart = time.Now()
				return nil
			}
			return err
		}

		json.Unmarshal([]byte(val), remoteAddressRequestCounters)
		return nil
	})

	fmt.Println(remoteAddressRequestCounters)

	// update request counters for remote address and user
	rl.db.Update(func(tx *buntdb.Tx) error {
		var err error
		remoteAddressRequestCounters.Global += 1
		if state.Path.Table != "" {
			if remoteAddressRequestCounters.Table == nil {
				remoteAddressRequestCounters.Table = map[string]*TableRequestCounters{}
			}
			if _, ok := remoteAddressRequestCounters.Table[state.Path.Table]; !ok {
				remoteAddressRequestCounters.Table[state.Path.Table] = &TableRequestCounters{MethodCount: make(map[string]int)}
			}
			remoteAddressRequestCounters.Table[state.Path.Table].MethodCount[state.Method] += 1
		}
		if state.Path.Function != "" {
			if remoteAddressRequestCounters.Function == nil {
				remoteAddressRequestCounters.Function = make(map[string]int)
			}
			remoteAddressRequestCounters.Function[state.Path.Function] += 1
		}

		b, _ := json.Marshal(remoteAddressRequestCounters)

		// need to calculate when to auto expire this value, everytime the value is set, the TTL gets reset
		// we want the TTL to be the lifetime of the bucket, not the time since last update
		ttlRemaining := expireTime - time.Since(remoteAddressRequestCounters.BucketStart)
		_, _, err = tx.Set(state.RemoteAddress, string(b), &buntdb.SetOptions{Expires: true, TTL: ttlRemaining})

		if err != nil {
			return err
		}
		return nil
	})

	response := &pb.RateLimitResponse{}
	response.Statuses = make([]*pb.RateLimitResponse_DescriptorStatus, 1)
	// response.Statuses[0] = &pb.RateLimitResponse_DescriptorStatus{
	// 	Code:           pb.RateLimitResponse_OK,
	// 	CurrentLimit:   nil,
	// 	LimitRemaining: 100,
	// }
	limit := &pb.RateLimitResponse_RateLimit{}
	response.Statuses[0] = &pb.RateLimitResponse_DescriptorStatus{
		Code:           pb.RateLimitResponse_OVER_LIMIT,
		CurrentLimit:   limit,
		LimitRemaining: 0,
	}
	fmt.Println("limiter")
	return response, nil
}
