package iv

import "crypto/rand"

type RandomIvGenerator struct {
}

func (g RandomIvGenerator) GenerateIv(lengthBytes int) ([]byte, error) {
	salt := make([]byte, lengthBytes)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func (g RandomIvGenerator) IncludePlainIvInEncryptionResults() bool {
	return true
}
