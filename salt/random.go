package salt

import "crypto/rand"

type RandomSaltGenerator struct {
}

func (g RandomSaltGenerator) GenerateSalt(lengthBytes int) ([]byte, error) {
	salt := make([]byte, lengthBytes)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func (g RandomSaltGenerator) IncludePlainSaltInEncryptionResults() bool {
	return true
}
