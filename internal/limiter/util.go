package limiter

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt"
)

type PathParts struct {
	Table    string
	Function string
	Columns  []string
	Filters  map[string]string
}

func parsePath(path string) PathParts {
	parsedPath := PathParts{}
	u, _ := url.Parse(path)
	query := u.Query()
	p := strings.Replace(u.Path, "/rest/v1", "", 1)
	if strings.HasPrefix(p, "/rpc/") {
		parsedPath.Function = strings.SplitAfter(p, "/")[2]
	} else {
		parsedPath.Table = strings.Replace(p, "/", "", 1)
	}

	for q, p := range query {
		switch q {
		case "select":
			columns := strings.Split(p[0], ",")
			// remove casting
			for k, v := range columns {
				columns[k] = strings.SplitN(v, "::", 2)[0]
			}
			parsedPath.Columns = columns
		default:
			if parsedPath.Filters == nil {
				parsedPath.Filters = make(map[string]string)
			}
			parsedPath.Filters[q] = p[0]
		}
	}
	return parsedPath
}

func validateToken(tokenString string, hmacSecret []byte) (jwt.MapClaims, error) {
	// remove bearer keyword if present
	if ts := strings.Split(tokenString, " "); len(ts) == 2 {
		tokenString = ts[1]
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return hmacSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims, nil
	}
	return nil, nil
}

func extractJWT(hmacSecret []byte, authString string) jwt.MapClaims {
	if authString != "" {
		// validate token
		jwt, err := validateToken(authString, hmacSecret)
		if err == nil && jwt != nil {
			return jwt
		}
	}
	return nil
}

func extractSQLMethod(method, prefer string) string {
	// add method
	switch method {
	case "GET":
		return "SELECT"
	case "POST":
		// check if INSERT or UPSERT POST
		if prefer == "resolution=merge-duplicates" {
			return "UPSERT"
		}
		return "INSERT"
	case "PATCH":
		return "UPDATE"
	case "PUT":
		return "UPSERT"
	case "DELETE":
		return "DELETE"
	}
	return ""
}
