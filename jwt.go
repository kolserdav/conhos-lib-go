package conhoslib

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func ParseJWT(tokenString string, jwtKey string) (*jwt.Claims, *Error) {

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signature method %v", token.Header["alg"])
		}
		return []byte(jwtKey), nil
	})

	if err != nil {
		return nil, NewError(err.Error())
	}

	if !token.Valid {
		return nil, NewError("token is invalid")
	}

	return &token.Claims, nil
}
