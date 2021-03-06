package encryption

import (
	"github.com/Mystery00/go-jasypt/iv"
	"github.com/Mystery00/go-jasypt/salt"
)

type Encryptor interface {
	Encrypt(message string) (string, error)
	Decrypt(message string) (string, error)
}

type EncryptorConfig struct {
	Password      string
	SaltGenerator salt.Generator
	IvGenerator   iv.Generator
}
