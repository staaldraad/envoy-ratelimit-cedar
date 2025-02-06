package main

import (
	"flag"
	"fmt"
	"net"

	pb "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/staaldraad/envoy-ratelimit-cedar/internal/limiter"
	"google.golang.org/grpc"
)

func main() {

	hmacSecretPtr := flag.String("hmac", "", "a secret to sign the jwt")
	pathPtr := flag.String("path", "limit.cedar", "path to the policy file to use")
	flag.Parse()

	if *pathPtr == "" {
		fmt.Println("requires --path value")
		return
	}

	if *hmacSecretPtr == "" {
		fmt.Println("requires --hmac value")
		return
	}

	endPoint := fmt.Sprintf("localhost:%d", 3007)
	listen, _ := net.Listen("tcp", endPoint)

	grpcServer := grpc.NewServer()

	service := &limiter.RateLimitServer{HMACSecret: []byte(*hmacSecretPtr)}
	go service.StartBackend("data.db")

	pb.RegisterRateLimitServiceServer(grpcServer, service)

	grpcServer.Serve(listen)
}
