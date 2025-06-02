package symmetric

import (
	"encoding/base64"
	"encoding/json"
)

type EncryptedData struct {
	Nonce      []byte
	Ciphertext []byte
}

func (e *EncryptedData) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Nonce      string `json:"nonce"`
		Ciphertext string `json:"ciphertext"`
	}{
		Nonce:      base64.StdEncoding.EncodeToString(e.Nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(e.Ciphertext),
	})
}

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
