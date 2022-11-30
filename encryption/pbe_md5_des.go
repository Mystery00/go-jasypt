package encryption

import (
	"encoding/base64"
	"regexp"
)

type PBEWithMD5AndDES struct {
	config EncryptorConfig
}

func NewPBEWithMD5AndDES(config EncryptorConfig) *PBEWithMD5AndDES {
	return &PBEWithMD5AndDES{
		config: config,
	}
}

func (enc *PBEWithMD5AndDES) Encrypt(message string) (string, error) {
	saltGenerator := enc.config.SaltGenerator
	ivGenerator := enc.config.IvGenerator
	password := enc.config.Password
	algorithmBlockSize := 8
	keyObtentionIterations := 1000

	salt, err := saltGenerator.GenerateSalt(algorithmBlockSize)
	if err != nil {
		return "", err
	}
	iv, err := ivGenerator.GenerateIv(algorithmBlockSize)
	if err != nil {
		return "", err
	}

	dk, iv := getMd5DerivedKey(password, salt, keyObtentionIterations)
	encText, err := desEncrypt([]byte(message), dk, iv)
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

func (enc *PBEWithMD5AndDES) Decrypt(message string) (string, error) {
	saltGenerator := enc.config.SaltGenerator
	ivGenerator := enc.config.IvGenerator
	password := enc.config.Password
	algorithmBlockSize := 8
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
	dk, iv := getMd5DerivedKey(password, salt, keyObtentionIterations)
	text, err := desDecrypt(encrypted, dk, iv)
	if err != nil {
		return "", err
	}
	p := regexp.MustCompile(`[\x01-\x08]`)
	return p.ReplaceAllString(string(text), ""), nil
}
