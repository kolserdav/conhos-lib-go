package conhoslib

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

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

func LoadEd25519PrivateKey(keyFilePath string) (ed25519.PrivateKey, *Error) {
	data, readErr := os.ReadFile(keyFilePath)
	if readErr != nil {
		return nil, NewError(readErr.Error())
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, NewError("failed to decode PEM block")
	}

	// For OpenSSL >= 3.0
	if block.Type == "PRIVATE KEY" {
		privKey, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, NewError(parseErr.Error())
		}
		return privKey.(ed25519.PrivateKey), nil
	}

	// For old versions
	if block.Type == "OPENSSH PRIVATE KEY" {
		return nil, NewError("OpenSSH key format not supported, convert to PKCS8")
	}

	return nil, NewError("unsupported key format")
}
