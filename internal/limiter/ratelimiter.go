package limiter

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	cedar "github.com/cedar-policy/cedar-go"
	pb "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/golang-jwt/jwt"
)

const expireTime = time.Second * 60

type RateLimitServer struct {
	HMACSecret []byte
	backend    *BackendService
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
	rl.backend.StartBackend(path)
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

	fmt.Println(remoteAddressRequestCounters)
	fmt.Println(userRequestCounters)

	checkLimits(state, &userRequestCounters, &remoteAddressRequestCounters)
	// update request counters for remote address
	updateLimits(state, &remoteAddressRequestCounters)
	updateLimits(state, &userRequestCounters)

	rl.backend.BatchUpdate([]string{state.RemoteAddress, userId}, []RequestCounters{remoteAddressRequestCounters, userRequestCounters})
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

type Entity struct {
	Uid     EntityDef              `json:"uid"`
	Attrs   map[string]interface{} `json:"attrs"`
	Parents []EntityDef            `json:"parents"`
}
type EntityDef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

const alwaysPermit = `permit (
	principal,
	action,
	resource
);
`
const policyCedar = `forbid (
	principal,
	action == Action::"SELECT",
	resource in Table::"tbl"
  ) when {
	resource.requests > 5
	||
	context.total_requests > 10
  };
`

type attrs struct {
	User   int
	Remote int
}

func checkLimits(state *RequestState, userRateLimitCounter, remoteRateLimitCounter *RequestCounters) {
	ents := make([]Entity, 4)

	tableAttrs := make(map[string]interface{})
	if userRateLimitCounter.Table == nil {
		tableAttrs["requests"] = attrs{User: 0, Remote: 0}
	} else {
		if r, ok := userRateLimitCounter.Table.MethodCount[state.Method]; ok {
			tableAttrs["requests"] = attrs{User: r, Remote: 0}
		}
		if r, ok := remoteRateLimitCounter.Table.MethodCount[state.Method]; ok {
			tableAttrs["requests"] = attrs{User: tableAttrs["requests"].(attrs).User, Remote: r}
		}
	}
	funcAttrs := make(map[string]interface{})
	funcAttrs["requests"] = attrs{User: userRateLimitCounter.Function, Remote: remoteRateLimitCounter.Function}

	// Principals
	ents[0] = Entity{Uid: EntityDef{Type: "User", ID: "jwt"}, Attrs: state.Authorization}
	ents[1] = Entity{Uid: EntityDef{Type: "RemoteAddress", ID: state.RemoteAddress}}
	// Resources
	ents[2] = Entity{Uid: EntityDef{Type: "Table", ID: state.Path.Table}, Attrs: tableAttrs}
	ents[3] = Entity{Uid: EntityDef{Type: "Function", ID: state.Path.Function}, Attrs: funcAttrs}

	entitiesJSON, _ := json.Marshal(ents)
	fmt.Println(string(entitiesJSON))
	var entities cedar.EntityMap
	if err := json.Unmarshal([]byte(entitiesJSON), &entities); err != nil {
		fmt.Println(err)
		return
	}
	var resource cedar.EntityUID
	if state.Path.Table != "" {
		resource = cedar.NewEntityUID("Table", cedar.String(state.Path.Table))
	} else {
		resource = cedar.NewEntityUID("Function", cedar.String(state.Path.Function))
	}
	totalRequests := cedar.Long(userRateLimitCounter.Global)

	req := cedar.Request{
		Principal: cedar.NewEntityUID("User", cedar.String("jwt")),
		Action:    cedar.NewEntityUID("Action", cedar.String(state.Method)),
		Resource:  resource,
		Context: cedar.NewRecord(cedar.RecordMap{
			"remote_address": cedar.String(state.RemoteAddress),
			"total_requests": totalRequests,
		}),
	}
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(policyCedar)); err != nil {
		fmt.Println(err)
		return
	}
	var policyAllow cedar.Policy
	if err := policyAllow.UnmarshalCedar([]byte(alwaysPermit)); err != nil {
		fmt.Println(err)
		return
	}
	ps := cedar.NewPolicySet()
	ps.Add("policy0", &policyAllow)
	ps.Add("policy1", &policy)
	fmt.Println(req)
	if okk, diag := ps.IsAuthorized(entities, req); !okk {
		if len(diag.Errors) > 0 {
			fmt.Println((diag.Errors))
			return
		}
		fmt.Println("blocked request by policy")
		return
	}
}
