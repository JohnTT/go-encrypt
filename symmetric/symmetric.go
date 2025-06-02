// Package symmetric provides simple symmetric encryption and decryption
// using AES-GCM with a key derived from a passphrase via SHA-256.
package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
)

// CryptoManager manages symmetric encryption and decryption operations
// using AES-GCM. The encryption key is derived from a passphrase.
type CryptoManager struct {
	key []byte
}

// NewCryptoManager creates a new CryptoManager instance.
// The provided key string is hashed using SHA-256 to produce a 32-byte key.
func NewCryptoManager(key string) *CryptoManager {
	hash := sha256.Sum256([]byte(key))
	return &CryptoManager{key: hash[:]}
}

// Encrypt encrypts the given plaintext using AES-GCM.
// It returns an EncryptedData struct containing the nonce and ciphertext.
func (c *CryptoManager) Encrypt(plaintext []byte) (*EncryptedData, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return &EncryptedData{Nonce: nonce, Ciphertext: ciphertext}, nil
}

// Decrypt decrypts the provided EncryptedData using AES-GCM.
// It returns the original plaintext if decryption is successful.
func (c *CryptoManager) Decrypt(data EncryptedData) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, data.Nonce, data.Ciphertext, nil)
}
