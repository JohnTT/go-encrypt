package symmetric

import (
	"encoding/json"
	"log"
	"testing"
)

// TestDecrypt verifies the encryption and decryption process of SymmetricCrypter.
// It checks that:
// - Data can be encrypted and marshaled to JSON.
// - The resulting JSON contains the expected fields ("nonce" and "ciphertext").
// - Data can be unmarshaled and decrypted back to the original plaintext.
func TestDecrypt(t *testing.T) {
	key := "my_secret_key"
	cm := NewSymmetricCrypter(key)

	// Create a new token object
	plainText := "my_access_token"

	var encryptedJSON []byte
	{
		encryptedData, err := cm.Encrypt([]byte(plainText))
		if err != nil {
			t.Fatalf("Failed to encrypt token: %v", err)
		}
		// Marshal the encrypted data to JSON
		encryptedJSON, err = encryptedData.MarshalJSON()
		if err != nil {
			t.Fatalf("Failed to marshal encrypted data: %v", err)
		}

	}
	log.Printf("Encrypted JSON: %s", encryptedJSON)

	// Parse the JSON and check for expected fields
	var result map[string]interface{}
	if err := json.Unmarshal(encryptedJSON, &result); err != nil {
		t.Fatalf("Failed to unmarshal encrypted JSON: %v", err)
	}
	for _, field := range []string{"nonce", "ciphertext"} {
		if _, ok := result[field]; !ok {
			t.Errorf("Missing expected field: %s", field)
		}
	}

	encryptedData := &EncryptedData{}
	if err := encryptedData.UnmarshalJSON(encryptedJSON); err != nil {
		t.Fatalf("Failed to unmarshal encrypted data: %v", err)
	}
	decryptedBytes, err := cm.Decrypt(*encryptedData)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	decryptedString := string(decryptedBytes)
	if decryptedString != plainText {
		t.Errorf("Decrypted string does not match original: got %s, want %s", decryptedString, plainText)
	}
	log.Printf("Decrypted string: %s", decryptedString)
}
