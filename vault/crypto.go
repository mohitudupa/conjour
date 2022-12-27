package vault

import (
	"mohitudupa/conjure/utils"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	BlockSize = 256
	IterCount = 50000
	KeySize   = 32
	NonceSize = 12
	SaltSize  = 32
)

// GenerateKey generates a new AES encryption key of size KeySize
func GenerateKey(password string, salt string) *[]byte {
	key := pbkdf2.Key(
		[]byte(password),
		[]byte(salt), IterCount, KeySize, sha256.New)
	return &key
}

// GenerateSalt creates a new random salt that can be used for key generation of size SaltSize
func GenerateSalt() (*[]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	return &salt, nil
}

// GenerateNonce generates a random nounce of size NonceSize
func GenerateNonce() (*[]byte, error) {
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return &nonce, nil
}

// Encrypt encrypts a byte array with a given password and salt
func Encrypt(password string, salt string, blob *[]byte) (*[]byte, error) {
	key := GenerateKey(password, salt)

	block, err := aes.NewCipher(*key)
	if err != nil {
		utils.ErrorLogger.Println("Could not create AES cipher")
		return nil, err
	}

	nonce, err := GenerateNonce()
	if err != nil {
		utils.ErrorLogger.Println("Could not create random nounce")
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		utils.ErrorLogger.Println("Could not create AES-GSM cipher")
		return nil, err
	}

	cipherText := append(*nonce, aesgcm.Seal(nil, *nonce, *blob, nil)...)

	return &cipherText, nil
}

// Decrypt decrypts a byte array with a given password and salt
func Decrypt(password string, salt string, blob *[]byte) (*[]byte, error) {
	key := GenerateKey(password, salt)

	block, err := aes.NewCipher(*key)
	if err != nil {
		utils.ErrorLogger.Println("Could not create AES cipher")
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		utils.ErrorLogger.Println("Could not create AES-GSM cipher")
		return nil, err
	}

	nonce := (*blob)[:NonceSize]
	cypherText := (*blob)[NonceSize:]

	PlainText, err := aesgcm.Open(nil, nonce, cypherText, nil)
	if err != nil {
		utils.ErrorLogger.Println("Could not decrypt cypher text")
		return nil, err
	}

	return &PlainText, nil
}
