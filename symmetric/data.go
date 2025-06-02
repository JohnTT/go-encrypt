package symmetric

import (
	"encoding/base64"
	"encoding/json"
)

// EncryptedData represents data encrypted with a symmetric cipher.
// It contains the nonce (initialization vector) and the ciphertext.
// Both fields are stored as byte slices.
type EncryptedData struct {
	Nonce      []byte // Nonce used for encryption (e.g., IV or GCM nonce)
	Ciphertext []byte // The encrypted data
}

// MarshalJSON implements the json.Marshaler interface for EncryptedData.
// It encodes the Nonce and Ciphertext fields as base64 strings for safe JSON transport.
func (e *EncryptedData) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Nonce      string `json:"nonce"`
		Ciphertext string `json:"ciphertext"`
	}{
		Nonce:      base64.StdEncoding.EncodeToString(e.Nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(e.Ciphertext),
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface for EncryptedData.
// It decodes base64-encoded Nonce and Ciphertext fields from JSON into byte slices.
func (e *EncryptedData) UnmarshalJSON(data []byte) error {
	aux := &struct {
		Nonce      string `json:"nonce"`
		Ciphertext string `json:"ciphertext"`
	}{}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	var err error
	e.Nonce, err = base64.StdEncoding.DecodeString(aux.Nonce)
	if err != nil {
		return err
	}
	e.Ciphertext, err = base64.StdEncoding.DecodeString(aux.Ciphertext)
	return err
}
