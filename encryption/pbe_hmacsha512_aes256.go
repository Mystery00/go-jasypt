package encryption

import (
	"crypto/sha512"
	"encoding/base64"
	"golang.org/x/crypto/pbkdf2"
	"regexp"
)

type PBEWithHMACSHA512AndAES_256 struct {
	config EncryptorConfig
}

func NewPBEWithHMACSHA512AndAES_256(config EncryptorConfig) *PBEWithHMACSHA512AndAES_256 {
	return &PBEWithHMACSHA512AndAES_256{
		config: config,
	}
}

func (enc *PBEWithHMACSHA512AndAES_256) Encrypt(message string) (string, error) {
	saltGenerator := enc.config.SaltGenerator
	ivGenerator := enc.config.IvGenerator
	password := enc.config.Password
	algorithmBlockSize := 16
	keyObtentionIterations := 1000

	salt, err := saltGenerator.GenerateSalt(algorithmBlockSize)
	if err != nil {
		return "", err
	}
	iv, err := ivGenerator.GenerateIv(algorithmBlockSize)
	if err != nil {
		return "", err
	}

	dk := pbkdf2.Key([]byte(password), salt, keyObtentionIterations, 32, sha512.New)
	encText, err := aes256Encrypt([]byte(message), dk, iv)
	if err != nil {
		return "", err
	}
	result := encText
	if ivGenerator.IncludePlainIvInEncryptionResults() {
		result = append(iv, result...)
	}
	if saltGenerator.IncludePlainSaltInEncryptionResults() {
		result = append(salt, result...)
	}
	//执行Base64编码
	encodeString := base64.StdEncoding.EncodeToString(result)
	return encodeString, nil
}

func (enc *PBEWithHMACSHA512AndAES_256) Decrypt(message string) (string, error) {
	saltGenerator := enc.config.SaltGenerator
	ivGenerator := enc.config.IvGenerator
	password := enc.config.Password
	algorithmBlockSize := 16
	keyObtentionIterations := 1000

	//Base64解码
	encrypted, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", err
	}
	var salt []byte
	var iv []byte
	if saltGenerator.IncludePlainSaltInEncryptionResults() {
		salt = encrypted[:algorithmBlockSize]
		encrypted = encrypted[algorithmBlockSize:]
	}
	if ivGenerator.IncludePlainIvInEncryptionResults() {
		iv = encrypted[:algorithmBlockSize]
		encrypted = encrypted[algorithmBlockSize:]
	}
	dk := pbkdf2.Key([]byte(password), salt, keyObtentionIterations, 32, sha512.New)
	text, err := aes256Decrypt(encrypted, dk, iv)
	if err != nil {
		return "", err
	}
	p := regexp.MustCompile(`[\x01-\x08]`)
	return p.ReplaceAllString(string(text), ""), nil
}
