package conhoslib

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	conhoslib "github.com/kolserdav/conhos-lib/pkg/lib"
)

func ParseJWT(tokenString string, jwtKey string) (*jwt.Claims, *conhoslib.Error) {

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signature method %v", token.Header["alg"])
		}
		return []byte(jwtKey), nil
	})

	if err != nil {
		return nil, conhoslib.NewError(err.Error())
	}

	if !token.Valid {
		return nil, conhoslib.NewError("token is invalid")
	}

	return &token.Claims, nil
}
