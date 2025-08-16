package conhoslib

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTToken struct {
	Id       string
	Password string
}

func CreateToken(scope string, username string, now time.Time, secure bool) (string, *Error) {
	var access []map[string]interface{}

	var checkScopeErr *Error
	var userRegistry, repoName string
	if scope != "" {
		scopeList := strings.Fields(scope)

		for _, singleScope := range scopeList {
			parts := strings.Split(singleScope, ":")
			repoList := strings.Split(parts[1], "/")
			userRegistry = repoList[0]
			if len(repoList) > 1 {
				repoName = repoList[1]
			} else {
				repoName = "*"
			}
			if secure && userRegistry != username {
				checkScopeErr = NewError(fmt.Sprintf("Forbidden repository namespace: %s/%s", userRegistry, repoName))
			}

			if len(parts) == 3 {
				access = append(access, map[string]interface{}{
					"type":    parts[0],
					"name":    parts[1],
					"actions": strings.Split(parts[2], ","),
				})
			}
		}
	} else {
		access = append(access, map[string]interface{}{
			"type":    TYPE,
			"name":    username + "/*",
			"actions": []string{"pull", "push"},
		})
	}
	if checkScopeErr != nil {
		return "warn", checkScopeErr
	}

	claims := jwt.MapClaims{
		"iss":    TOKEN_ISSUER,
		"sub":    username,
		"aud":    AUD,
		"exp":    now.Add(1 * time.Hour).Unix(),
		"iat":    now.Unix(),
		"nbf":    now.Unix(),
		"access": access,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = TOKEN_KID

	privateKey, err := LoadEd25519PrivateKey(KEY_FILEPATH)
	if err != nil {
		return "", NewError(err.Error())
	}

	tokenString, signErr := token.SignedString(privateKey)
	if signErr != nil {
		return tokenString, NewError(signErr.Error())
	}

	return tokenString, nil
}

func ParseJWT(tokenString string, jwtKey string) (*JWTToken, *Error) {

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

	var id, password string
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		for key, val := range claims {
			value := fmt.Sprintf("%s", val)
			switch key {
			case "id":
				id = value
			case "password":
				password = value
			}
		}
	} else {
		return nil, NewError("failed to get token claims")
	}

	return &JWTToken{Id: id, Password: password}, nil
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
