package server

import (
	"encoding/base64"
	"errors"
	"strings"

	"mohitudupa/conjure/utils"
)

// Auth is used to store the Basic auth cerdentials
type Auth struct {
	Username string
	password string
}

// BasicAuth accepts the Authorization value of the HTTP request and extracts the
// BasicAuth credentials
func BasicAuth(basicAuthToken string) (*Auth, error) {
	b64AuthToken := strings.Replace(basicAuthToken, "Basic ", "", 1)

	// Decode base64 string to ascii/utf-8
	decodedBasicAuthToken, err := base64.StdEncoding.DecodeString(b64AuthToken)
	if err != nil {
		utils.ErrorLogger.Println("Could not decode Basic Auth Token")
		return nil, errors.New("Could not decode Basic Auth Token")
	}

	splitToken := strings.Split(string(decodedBasicAuthToken), ":")
	if len(splitToken) != 2 {
		utils.ErrorLogger.Println("Invalid Basic Auth Token")
		return nil, errors.New("Invalid Basic Auth Token")
	}

	return &Auth{
		Username: splitToken[0],
		password: splitToken[1],
	}, nil
}
