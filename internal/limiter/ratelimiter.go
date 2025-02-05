package limiter

import (
	"context"
	"fmt"

	pb "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/golang-jwt/jwt"
)

type RateLimitServer struct {
	HMACSecret []byte
}

type RequestState struct {
	RawPath       string
	Path          PathParts
	RemoteAddress string
	Authorization jwt.MapClaims
	Method        string
}

func (rl *RateLimitServer) ShouldRateLimit(ctx context.Context, request *pb.RateLimitRequest) (*pb.RateLimitResponse, error) {

	state := &RequestState{}
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
				state.Method = extractSQLMethod(request.Descriptors[i].Entries[j].Value, "")
			}
		}
	}
	fmt.Println(state)

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
