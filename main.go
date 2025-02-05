package main

import (
	"fmt"
	"net"

	pb "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/staaldraad/envoy-ratelimit-cedar/internal/limiter"
	"google.golang.org/grpc"
)

func main() {

	fmt.Println("woot")

	endPoint := fmt.Sprintf("localhost:%d", 3007)
	listen, _ := net.Listen("tcp", endPoint)

	grpcServer := grpc.NewServer()

	service := &limiter.RateLimitServer{}

	pb.RegisterRateLimitServiceServer(grpcServer, service)

	grpcServer.Serve(listen)
}
