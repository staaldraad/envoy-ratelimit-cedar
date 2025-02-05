package limiter

import (
	"context"
	"fmt"

	pb "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
)

type RateLimitServer struct {
}

func (rl *RateLimitServer) ShouldRateLimit(ctx context.Context, request *pb.RateLimitRequest) (*pb.RateLimitResponse, error) {

	fmt.Println(request.GetDescriptors())
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
