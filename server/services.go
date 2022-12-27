package server

import (
	"mohitudupa/conjure/utils"
	"mohitudupa/conjure/vault"

	"errors"

	"github.com/gin-gonic/gin"
)

const (
	storePath = "/home/frost/"
)

// ListSecretsHandler is the HTTP handler for ListSecretsURL
func ListSecretsHandler(c *gin.Context) {
	c.Header("content-type", "application/json")

	// Load Vault store
	vaultStore, err := vault.InitVault(storePath, "")
	if err != nil {
		utils.ErrorLogger.Printf("Internal Server Occured. Error: %v", err)
		e := ErrorResponse{Error: "Internal Server Occured"}
		c.JSON(500, e)
		return
	}

	// Return list of secrets
	resp := ListSecretsResponse{
		Secrets: *vaultStore.ListSecrets(),
	}
	c.JSON(200, resp)
}

// GetSecretsHandler is the HTTP handler for GetSecretsURL
func GetSecretsHandler(c *gin.Context) {
	c.Header("content-type", "application/json")

	secretName := c.Param("name")

	// Load BasicAuth credentials from request headers
	auth, err := BasicAuth(c.GetHeader("Authorization"))
	if err != nil {
		e := ErrorResponse{Error: err.Error()}
		c.JSON(401, e)
		return
	}

	// Load Vault store
	vaultStore, err := vault.InitVault(storePath, auth.password)
	if err != nil {
		utils.ErrorLogger.Printf("Internal Server Occured. Error: %v", err)
		e := ErrorResponse{Error: "Internal Server Occured"}
		c.JSON(500, e)
		return
	}

	// Get secret
	secret, err := vaultStore.GetSecret(secretName)
	if errors.Is(err, vault.SecretNotFoundError) {
		e := ErrorResponse{Error: err.Error()}
		c.JSON(404, e)
		return
	} else if errors.Is(err, vault.IncorrectCredentialsError) {
		e := ErrorResponse{Error: err.Error()}
		c.JSON(401, e)
		return
	} else if err != nil {
		utils.ErrorLogger.Printf("Internal Server Occured. Error: %v", err)
		e := ErrorResponse{Error: "Internal Server Occured"}
		c.JSON(500, e)
		return
	}

	// Return response
	c.JSON(200, GetSecretsResponse{
		Name:     secretName,
		Username: secret.Username,
		Password: secret.Password,
		URL:      secret.URL,
		Email:    secret.Email,
		Notes:    secret.Notes,
	})
}

// UpdateSecretsHandler is the HTTP handler for UpdateSecretsURL
func UpdateSecretsHandler(c *gin.Context) {
	c.Header("content-type", "application/json")

	secretName := c.Param("name")

	// Load BasicAuth credentials from request headers
	auth, err := BasicAuth(c.GetHeader("Authorization"))
	if err != nil {
		e := ErrorResponse{Error: err.Error()}
		c.JSON(401, e)
		return
	}

	// Load Vault store
	vaultStore, err := vault.InitVault(storePath, auth.password)
	if err != nil {
		utils.ErrorLogger.Printf("Internal Server Occured. Error: %v", err)
		e := ErrorResponse{Error: "Internal Server Occured"}
		c.JSON(500, e)
		return
	}

	// Read PUT request body
	req := UpdateSecretsRequest{}
	if err := c.ShouldBindJSON(&req); err != nil {
		// Return a 400 bad request
		e := ErrorResponse{Error: err.Error()}
		c.JSON(400, e)
		return
	}

	// Create new secret
	secret := vault.NewSecret(
		secretName, req.Username, req.Password, req.URL, req.Email, req.Notes,
	)

	// Add new secret to Vault store
	err = vaultStore.UpdateSecret(secret)
	if errors.Is(err, vault.IncorrectCredentialsError) {
		e := ErrorResponse{Error: err.Error()}
		c.JSON(401, e)
		return
	} else if err != nil {
		utils.ErrorLogger.Printf("Internal Server Occured. Error: %v", err)
		e := ErrorResponse{Error: "Internal Server Occured"}
		c.JSON(500, e)
		return
	}

	// Return response
	c.JSON(200, UpdateSecretsResponse{
		Name: secretName,
	})
}

// DeleteSecretsHandler is the HTTP handler for DeleteSecretsURL
func DeleteSecretsHandler(c *gin.Context) {
	c.Header("content-type", "application/json")

	secretName := c.Param("name")

	// Load BasicAuth credentials from request headers
	auth, err := BasicAuth(c.GetHeader("Authorization"))
	if err != nil {
		e := ErrorResponse{Error: err.Error()}
		c.JSON(401, e)
		return
	}

	// Load Vault store
	vaultStore, err := vault.InitVault(storePath, auth.password)
	if err != nil {
		utils.ErrorLogger.Printf("Internal Server Occured. Error: %v", err)
		e := ErrorResponse{Error: "Internal Server Occured"}
		c.JSON(500, e)
		return
	}

	// Delete secret from store
	err = vaultStore.DeleteSecret(secretName)
	if errors.Is(err, vault.SecretNotFoundError) {
		e := ErrorResponse{Error: err.Error()}
		c.JSON(404, e)
		return
	} else if errors.Is(err, vault.IncorrectCredentialsError) {
		e := ErrorResponse{Error: err.Error()}
		c.JSON(401, e)
		return
	} else if err != nil {
		utils.ErrorLogger.Printf("Internal Server Occured. Error: %v", err)
		e := ErrorResponse{Error: "Internal Server Occured"}
		c.JSON(500, e)
		return
	}

	// Return response
	c.JSON(200, UpdateSecretsResponse{
		Name: secretName,
	})
}
