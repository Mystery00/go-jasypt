package jasypt

import (
	"github.com/Mystery00/go-jasypt/encryption"
	"github.com/Mystery00/go-jasypt/iv"
	"github.com/Mystery00/go-jasypt/salt"
)

func New(algorithm string, config encryption.EncryptorConfig) encryption.Encryptor {
	switch algorithm {
	case "PBEWithHMACSHA512AndAES_256":
		return encryption.NewPBEWithHMACSHA512AndAES_256(config)
	case "PBEWithMD5AndDES":
		return encryption.NewPBEWithMD5AndDES(config)
	default:
		panic(`unknown algorithm`)
	}
}

type Config func(*encryption.EncryptorConfig)

func NewConfig(configList ...Config) encryption.EncryptorConfig {
	encryptorConfig := encryption.EncryptorConfig{}
	for _, c := range configList {
		c(&encryptorConfig)
	}
	return encryptorConfig
}

func SetPassword(password string) Config {
	return func(encryptorConfig *encryption.EncryptorConfig) {
		encryptorConfig.Password = password
	}
}

func SetSaltGenerator(generator salt.Generator) Config {
	return func(encryptorConfig *encryption.EncryptorConfig) {
		encryptorConfig.SaltGenerator = generator
	}
}

func SetIvGenerator(generator iv.Generator) Config {
	return func(encryptorConfig *encryption.EncryptorConfig) {
		encryptorConfig.IvGenerator = generator
	}
}
