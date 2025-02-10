package limiter

import (
	"context"
	"time"

	pb "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/golang-jwt/jwt"
	"google.golang.org/protobuf/types/known/durationpb"
)

const expireTime = time.Second * 60

type RateLimitServer struct {
	HMACSecret []byte
	backend    *BackendService
	authorizer *Authorizer
}

type RequestState struct {
	RawPath       string
	Path          PathParts
	RemoteAddress string
	Authorization jwt.MapClaims
	Method        string
}

// set the json values as single chars to save space in buntdb
type RequestCounters struct {
	BucketStart time.Time             `json:"s"` // when did this request counter first start
	Global      int64                 `json:"g"` // total requests
	Table       *TableRequestCounters `json:"t"` // requests by path
	Function    int                   `json:"f"` // requests for function
}

type TableRequestCounters struct {
	MethodCount map[string]int `json:"m"`
}

func (rl *RateLimitServer) StartBackend(path string) error {
	rl.backend = &BackendService{}
	go rl.backend.StartBackend(path)
	rl.authorizer = &Authorizer{}
	go rl.authorizer.InitAuthorizer("ratelimit.cedar")
	return nil
}

func (rl *RateLimitServer) ShouldRateLimit(ctx context.Context, request *pb.RateLimitRequest) (*pb.RateLimitResponse, error) {
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

	// get IP limits
	remoteAddressRequestCounters, _ := rl.backend.Get(state.RemoteAddress)
	// get User limits
	var userId string
	if v, ok := state.Authorization["role"]; ok && v == "anon" {
		userId = "anon"
	} else if ok && v == "service_role" {
		userId = "service_role"
	} else if v, ok := state.Authorization["id"]; ok {
		userId = v.(string)
	}
	userRequestCounters, _ := rl.backend.Get(userId)
	response := &pb.RateLimitResponse{}
	response.Statuses = make([]*pb.RateLimitResponse_DescriptorStatus, 1)

	allow, source, _ := rl.authorizer.CheckLimits(state, &userRequestCounters, &remoteAddressRequestCounters)

	if !allow {
		var secondsToReset int64
		if source == "jwt" {
			secondsToReset = int64((expireTime - time.Since(userRequestCounters.BucketStart)).Seconds())
		} else {
			secondsToReset = int64((expireTime - time.Since(remoteAddressRequestCounters.BucketStart)).Seconds())
		}

		limit := &pb.RateLimitResponse_RateLimit{}
		response.Statuses[0] = &pb.RateLimitResponse_DescriptorStatus{
			Code:               pb.RateLimitResponse_OVER_LIMIT,
			CurrentLimit:       limit,
			LimitRemaining:     0,
			DurationUntilReset: &durationpb.Duration{Seconds: secondsToReset},
		}
		response.OverallCode = pb.RateLimitResponse_OVER_LIMIT
	} else {
		response.Statuses[0] = &pb.RateLimitResponse_DescriptorStatus{
			Code: pb.RateLimitResponse_OK,
		}
	}
	// update request counters for remote address
	updateLimits(state, &remoteAddressRequestCounters)
	updateLimits(state, &userRequestCounters)

	rl.backend.BatchUpdate([]string{state.RemoteAddress, userId}, []RequestCounters{remoteAddressRequestCounters, userRequestCounters})

	return response, nil
}

func updateLimits(state *RequestState, rateLimitCounter *RequestCounters) {
	if state.Path.Table != "" {
		if rateLimitCounter.Table == nil {
			rateLimitCounter.Table = &TableRequestCounters{MethodCount: make(map[string]int)}
		}
		rateLimitCounter.Table.MethodCount[state.Method] += 1
	}
	if state.Path.Function != "" {
		rateLimitCounter.Function += 1
	}
	// keep track of total requests
	rateLimitCounter.Global += 1
}
