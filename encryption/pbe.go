package encryption

import (
	"encoding/base64"
	"regexp"
)

type PBEWithMD5AndDES struct {
	config EncryptorConfig
}

func (enc *PBEWithMD5AndDES) Encrypt(message string) (string, error) {
	saltGenerator := enc.config.SaltGenerator
	ivGenerator := enc.config.IvGenerator
	password := enc.config.Password

	salt, err := saltGenerator.GenerateSalt(8)
	if err != nil {
		return "", err
	}
	iv, err := ivGenerator.GenerateIv(8)
	if err != nil {
		return "", err
	}
	//不知道什么意思
	padNum := 8 - (len(message) % 8)
	for i := 0; i <= padNum; i++ {
		message += string(rune(padNum))
	}
	//做MD5
	dk, iv := getMd5DerivedKey(password, salt, 1000)
	//做DES加密
	encText, err := desEncrypt([]byte(message), dk, iv)
	if err != nil {
		return "", err
	}
	result := encText
	if ivGenerator.IncludePlainIvInEncryptionResults() {
		result = append(salt, result...)
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

	//Base64解码
	encrypted, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", err
	}
	var salt []byte
	var iv []byte
	if saltGenerator.IncludePlainSaltInEncryptionResults() {
		salt = encrypted[:8]
		encrypted = encrypted[8:]
	}
	if ivGenerator.IncludePlainIvInEncryptionResults() {
		iv = encrypted[:8]
		encrypted = encrypted[8:]
	}
	dk, iv := getMd5DerivedKey(password, salt, 1000)
	text, err := desDecrypt(encrypted, dk, iv)
	if err != nil {
		return "", err
	}
	p := regexp.MustCompile(`[\x01-\x08]`)
	return p.ReplaceAllString(string(text), ""), nil
}
