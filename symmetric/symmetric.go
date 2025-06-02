package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
)

type CryptoManager struct {
	key []byte
}

func NewCryptoManager(key string) *CryptoManager {
	hash := sha256.Sum256([]byte(key))
	return &CryptoManager{key: hash[:]}
}

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
