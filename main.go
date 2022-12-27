package main

import (
	"mohitudupa/conjure/server"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	r.GET(server.ListSecretsURL, server.ListSecretsHandler)
	r.GET(server.GetSecretsURL, server.GetSecretsHandler)
	r.POST(server.UpdateSecretsURL, server.UpdateSecretsHandler)
	r.PUT(server.UpdateSecretsURL, server.UpdateSecretsHandler)
	r.DELETE(server.DeleteSecretsURL, server.DeleteSecretsHandler)

	r.Run(":3000")
}

/*
secret := vault.NewSecret(
		"toad", "bobby", "bobby's super secret password",
		"https://www.toad.co.in/", "bobby@toad.co.in",
		"Bobby's toad account :p")

	password := "bobby's super secret master password"
	InvalidPassword := "someone trying to hack bobby"
	vaultStore, err := vault.InitVault(storePath, password)
	if err != nil {
		vault.FatalLogger.Fatalf("Could not load vault. Error: %v", err)
	}

	fmt.Println(vaultStore.ListSecrets())

	vaultStore.UpdateSecret(secret)

	fmt.Println(vaultStore.ListSecrets())

	fmt.Println(vaultStore.GetSecret("toad"))

	vaultStore, err = vault.InitVault(storePath, InvalidPassword)
	if err != nil {
		vault.FatalLogger.Fatalf("Could not load vault. Error: %v", err)
	}

	fmt.Println(vaultStore.ListSecrets())

	fmt.Println(vaultStore.GetSecret("toad"))
*/
