package limiter

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt"
)

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
