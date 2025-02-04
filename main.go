package main

import (
	"context"
	"fmt"
	"net"

	pb "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"google.golang.org/grpc"
)

type RateLimitServer struct {
}

func (rl *RateLimitServer) ShouldRateLimit(ctx context.Context, request *pb.RateLimitRequest) (*pb.RateLimitResponse, error) {
	response := &pb.RateLimitResponse{}
	response.Statuses = make([]*pb.RateLimitResponse_DescriptorStatus, 1)
	response.Statuses[0] = &pb.RateLimitResponse_DescriptorStatus{
		Code:           pb.RateLimitResponse_OK,
		CurrentLimit:   nil,
		LimitRemaining: 100,
	}
	return response, nil
}

func main() {

	fmt.Println("woot")

	endPoint := fmt.Sprintf("localhost:%d", 3007)
	listen, _ := net.Listen("tcp", endPoint)

	grpcServer := grpc.NewServer()

	service := &RateLimitServer{}

	pb.RegisterRateLimitServiceServer(grpcServer, service)

	grpcServer.Serve(listen)
}
