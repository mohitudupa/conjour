package vault

import (
	"mohitudupa/conjure/utils"

	"encoding/json"
)

// Secret holds all the detals needed to save a password
type Secret struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
	Email    string `json:"email"`
	Notes    string `json:"notes"`
}

// NewSecret creates a new instance of Secret
func NewSecret(name string, username string, password string,
	url string, email string, notes string) *Secret {
	return &Secret{
		Name:     name,
		Username: username,
		Password: password,
		URL:      url,
		Email:    email,
		Notes:    notes,
	}
}

// LoadSecret reads in a byte array of a JSON secret and returns a Secret instance
func LoadSecret(blob *[]byte) (*Secret, error) {
	secret := &Secret{}
	err := json.Unmarshal(*blob, secret)
	if err != nil {
		utils.ErrorLogger.Println("Could not parse password json")
		return nil, err
	}

	return secret, nil
}

// DumpSecret converts a secret instance into a JSON byte array
func (p *Secret) DumpSecret() (*[]byte, error) {
	blob, err := json.Marshal(p)
	if err != nil {
		utils.ErrorLogger.Println("Could not convert password to json")
		return nil, err
	}

	return &blob, nil
}
