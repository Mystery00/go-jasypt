package encryption

import (
	"go-jasypt/iv"
	"go-jasypt/salt"
)

type EncryptorConfig struct {
	Password      string
	SaltGenerator salt.Generator
	IvGenerator   iv.Generator
}

type Encryptor interface {
	Encrypt(message string) (string, error)
	Decrypt(message string) (string, error)
}
