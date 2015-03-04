package models

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
)

func GeneratePasswordHash(id, pw, salt string) (string, error) {

	if salt == "" || id == "" {
		return "", errors.New("id and salt are required")
	}

	hash := sha1.New()
	if pw != "" {
		hash.Write([]byte(pw))
	}
	hash.Write([]byte(salt))
	hash.Write([]byte(id))
	pwHash := hex.EncodeToString(hash.Sum(nil))

	return pwHash, nil
}
