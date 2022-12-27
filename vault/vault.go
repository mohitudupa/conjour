package vault

import (
	"mohitudupa/conjure/utils"

	"encoding/json"
	"errors"
	"os"
	"path"
	"path/filepath"

	"github.com/google/uuid"
)

const (
	storeRoot   = ".conjure"
	storeConfig = "vault"
)

// Vault has all the data needed to manage the encrypted store
type Vault struct {
	Secrets  map[string]string `json:"secrets"`
	Salt     string            `json:"salt"`
	Store    string            `json:"store"`
	password string
}

// NewVault returns a new instance of Vault
func NewVault(password string, store string) (*Vault, error) {
	salt, err := GenerateSalt()
	if err != nil {
		utils.ErrorLogger.Println("Could not create new salt")
		return nil, err
	}
	return &Vault{
		Secrets:  map[string]string{},
		Salt:     string(*salt),
		password: password,
		Store:    store,
	}, nil
}

// LoadVault loads in a vault instance from a JSON byte array
func LoadVault(blob *[]byte) (*Vault, error) {
	vault := &Vault{}
	err := json.Unmarshal(*blob, vault)
	if err != nil {
		utils.ErrorLogger.Println("Could not load vault json")
		return nil, err
	}

	return vault, nil
}

// DumpVault converts a secret instance into a JSON byte array
func (v *Vault) DumpVault() (*[]byte, error) {
	blob, err := json.Marshal(v)
	if err != nil {
		utils.ErrorLogger.Println("Could not convert vault to json")
		return nil, err
	}

	return &blob, nil
}

// InitVault reads the vault srore on the system and returns an instance of Vault
func InitVault(userHome string, password string) (*Vault, error) {
	// Check if vault store exists in userHome
	storePath := path.Join(userHome, storeRoot)
	_, err := os.Stat(storePath)
	if err != nil {
		utils.WarnLogger.Printf("Vault store does not exist in %s. Creating new vault store", storePath)

		err := os.MkdirAll(storePath, 0700)
		if err != nil {
			utils.ErrorLogger.Printf("Could not create vault store in %s", storePath)
			return nil, errors.New("Could not create vault store in " + storePath)
		}

		utils.InfoLogger.Printf("New vault store created at %s", storePath)
	}

	storeConfigPath := path.Join(storePath, storeConfig)
	_, err = os.Stat(storeConfigPath)
	if err != nil {
		utils.WarnLogger.Printf("Vault store config does not exist in %s. Creating new vault store", storeConfigPath)

		vault, err := NewVault(password, storePath)
		if err != nil {
			return nil, err
		}

		vaultBlob, err := vault.DumpVault()
		if err != nil {
			return nil, err
		}

		err = os.WriteFile(storeConfigPath, *vaultBlob, 0600)
		if err != nil {
			utils.ErrorLogger.Println("Could not write vault state to store")
			return nil, err
		}

		utils.InfoLogger.Printf("New vault store configs created at %s", storeConfigPath)
		return vault, nil
	}

	blob, err := os.ReadFile(storeConfigPath)
	if err != nil {
		utils.ErrorLogger.Printf("Could not read vault state from store")
		return nil, err
	}

	vaultStore, err := LoadVault(&blob)
	if err != nil {
		return nil, err
	}
	vaultStore.password = password

	utils.InfoLogger.Printf("Loaded existing vault store configs at %s", storeConfigPath)
	return vaultStore, nil
}

// ListSecrets returns the list of secrets in the vault
func (v *Vault) ListSecrets() *[]string {
	keys := make([]string, 0, len(v.Secrets))
	for k := range v.Secrets {
		keys = append(keys, k)
	}
	utils.InfoLogger.Printf("%v", keys)
	return &keys
}

// GetSecret decrypts and returns a stored secret
func (v *Vault) GetSecret(secretName string) (*Secret, error) {
	secretFile, isPresent := v.Secrets[secretName]
	if !isPresent {
		return nil, SecretNotFoundError
	}

	// Read secretFile
	secretFilePath := filepath.Join(v.Store, secretFile)
	blob, err := os.ReadFile(secretFilePath)
	if err != nil {
		utils.ErrorLogger.Printf("Could not read secret file. Error: %v", err)
		return nil, SecretNotFoundError
	}

	// Decrypt message
	plainText, err := Decrypt(v.password, v.Salt, &blob)
	if err != nil {
		utils.ErrorLogger.Printf("Could not decrypt secret file. Error: %v", err)
		return nil, IncorrectCredentialsError
	}

	// Load Secret
	return LoadSecret(plainText)
}

// UpdateSecret creates a new secret or updates an existing secret in the vault store
func (v *Vault) UpdateSecret(secret *Secret) error {
	secretFile, isPresent := v.Secrets[secret.Name]
	if isPresent {
		// Secret is already present. Validate the password before proceeding to update the secret
		utils.WarnLogger.Printf("Secret: %s already exists. Updating secret", secret.Name)

		// Verify if the password is correct
		secretFilePath := filepath.Join(v.Store, secretFile)
		blob, err := os.ReadFile(secretFilePath)
		if err != nil {
			utils.ErrorLogger.Printf("Could not read secret file at %s", secretFilePath)
			return err
		}

		// Decrypt message
		_, err = Decrypt(v.password, v.Salt, &blob)
		if err != nil {
			utils.ErrorLogger.Printf("Could not decrypt secret file. Error: %v", err)
			return IncorrectCredentialsError
		}
	} else {
		// Generate secret file name
		secretFile = uuid.New().String()
	}

	// Convert secret object to json byte array
	blob, err := secret.DumpSecret()
	if err != nil {
		utils.ErrorLogger.Println("Could not convert secret type to Json")
		return err
	}

	// Encrypt secret
	cypherText, err := Encrypt(v.password, v.Salt, blob)
	if err != nil {
		utils.ErrorLogger.Println("Could not encrypt secret")
		return err
	}

	// Write new secretFile
	secretFilePath := filepath.Join(v.Store, secretFile)
	err = os.WriteFile(secretFilePath, *cypherText, 0600)
	if err != nil {
		utils.ErrorLogger.Println("Could not write encrypted secret to store")
		return err
	}

	v.Secrets[secret.Name] = secretFile

	// Write vault config to store
	vaultBlob, err := v.DumpVault()
	if err != nil {
		return err
	}
	vaultFilePath := filepath.Join(v.Store, storeConfig)
	err = os.WriteFile(vaultFilePath, *vaultBlob, 0600)
	if err != nil {
		utils.ErrorLogger.Println("Could not write vault state to store")
		return err
	}
	return nil
}

// DeleteSecret deletes a secret from vault store
func (v *Vault) DeleteSecret(secretName string) error {
	secretFile, isPresent := v.Secrets[secretName]
	if !isPresent {
		// Secret does not exist. Do nothing and return
		utils.ErrorLogger.Printf("Secret: %s does not exist. Nothing was deleted", secretName)
		return SecretNotFoundError
	}

	// Verify if the password is correct
	secretFilePath := filepath.Join(v.Store, secretFile)
	blob, err := os.ReadFile(secretFilePath)
	if err != nil {
		utils.ErrorLogger.Printf("Could not read secret file at %s", secretFilePath)
		return err
	}

	// Decrypt message
	_, err = Decrypt(v.password, v.Salt, &blob)
	if err != nil {
		utils.ErrorLogger.Printf("Could not decrypt secret file. Error: %v", err)
		return IncorrectCredentialsError
	}

	// Delete secret
	err = os.Remove(secretFilePath)
	if err != nil {
		utils.ErrorLogger.Printf("Could not delete secret in path: %s", secretFilePath)
		return err
	}

	// Deleting secret from vault state
	delete(v.Secrets, secretName)

	// Write vault config to store
	vaultBlob, err := v.DumpVault()
	if err != nil {
		return err
	}
	vaultFilePath := filepath.Join(v.Store, storeConfig)
	err = os.WriteFile(vaultFilePath, *vaultBlob, 0600)
	if err != nil {
		utils.ErrorLogger.Println("Could not write vault state to store")
		return err
	}
	return nil
}

/*
Create the following functions


UpdatePassword
*/
