package vault

import "errors"

var (
	SecretNotFoundError       = errors.New("Secret not found")
	IncorrectCredentialsError = errors.New("Provided credentials are incorrect")
)
