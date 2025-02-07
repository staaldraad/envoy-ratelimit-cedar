package limiter

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/fsnotify/fsnotify"
)

type Authorizer struct {
	policy *cedar.PolicySet
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

type attrs struct {
	User   int `json:"user"`
	Remote int `json:"remote"`
}

const alwaysPermitPolicy = `permit (
	principal,
	action,
	resource
);
`

func (auth *Authorizer) InitAuthorizer(path string) error {
	return auth.WatchFile(path)
}

func readFile(path string) ([]byte, error) {
	policyFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer policyFile.Close()

	rawPolicy, err := io.ReadAll(policyFile)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}
	return rawPolicy, nil
}

func (auth *Authorizer) WatchFile(path string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	//
	done := make(chan bool)

	//
	go func() {
		for {
			select {
			// watch for events
			case event := <-watcher.Events:
				if event.Op.String() == "WRITE" {
					// reload the file
					if rawPolicy, err := readFile(path); err != nil {
						fmt.Println(err)
					} else {
						auth.reloadPolicy(rawPolicy)
					}
				}
				// watch for errors
			case err := <-watcher.Errors:
				fmt.Println("ERROR", err)
			}
		}
	}()

	// out of the box fsnotify can watch a single file, or a single directory
	if err := watcher.Add(path); err != nil {
		fmt.Println("ERROR", err)
	}

	// initial load
	if rawPolicy, err := readFile(path); err != nil {
		return err
	} else {
		auth.reloadPolicy(rawPolicy)
	}
	<-done
	return nil
}

func (auth *Authorizer) reloadPolicy(rawPolicy []byte) error {
	var policyAllow cedar.Policy
	var err error
	if err = policyAllow.UnmarshalCedar([]byte(alwaysPermitPolicy)); err != nil {
		return err
	}

	auth.policy, err = cedar.NewPolicySetFromBytes("policy0", rawPolicy)
	if err != nil {
		return err
	}
	auth.policy.Add("nolimits", &policyAllow)
	return nil
}

func (auth *Authorizer) CheckLimits(state *RequestState, userRateLimitCounter, remoteRateLimitCounter *RequestCounters) (bool, string, error) {
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

	var entities cedar.EntityMap
	if err := json.Unmarshal([]byte(entitiesJSON), &entities); err != nil {
		return true, "", err
	}
	var resource cedar.EntityUID
	if state.Path.Table != "" {
		resource = cedar.NewEntityUID("Table", cedar.String(state.Path.Table))
	} else {
		resource = cedar.NewEntityUID("Function", cedar.String(state.Path.Function))
	}
	userTotalRequests := cedar.Long(userRateLimitCounter.Global)
	remoteTotalRequests := cedar.Long(remoteRateLimitCounter.Global)

	// check request for current user
	req := cedar.Request{
		Principal: cedar.NewEntityUID("User", cedar.String("jwt")),
		Action:    cedar.NewEntityUID("Action", cedar.String(state.Method)),
		Resource:  resource,
		Context: cedar.NewRecord(cedar.RecordMap{
			"remote_address":        cedar.String(state.RemoteAddress),
			"user_total_requests":   userTotalRequests,
			"remote_total_requests": remoteTotalRequests,
		}),
	}

	decision, diagnostic := auth.policy.IsAuthorized(entities, req)
	if !decision {
		return bool(decision), "jwt", nil
	}

	// check request for remote address
	req = cedar.Request{
		Principal: cedar.NewEntityUID("RemoteAddress", cedar.String(state.RemoteAddress)),
		Action:    cedar.NewEntityUID("Action", cedar.String(state.Method)),
		Resource:  resource,
		Context: cedar.NewRecord(cedar.RecordMap{
			"remote_address":        cedar.String(state.RemoteAddress),
			"user_total_requests":   userTotalRequests,
			"remote_total_requests": remoteTotalRequests,
		}),
	}

	decision, diagnostic = auth.policy.IsAuthorized(entities, req)
	if !decision {
		fmt.Println(diagnostic.Reasons)
	}

	return bool(decision), state.RemoteAddress, nil
}
