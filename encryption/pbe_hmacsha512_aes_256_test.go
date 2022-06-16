package encryption

import (
	"go-jasypt/iv"
	"go-jasypt/salt"
	"testing"
)

func TestPBEWithHMACSHA512AndAES_256(t *testing.T) {
	encryptor := PBEWithHMACSHA512AndAES_256{config: EncryptorConfig{
		Password:      "password",
		SaltGenerator: salt.RandomSaltGenerator{},
		IvGenerator:   iv.RandomIvGenerator{},
	}}
	encrypted, err := encryptor.Encrypt(`plain text`)
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf(`encrypted: %s`, encrypted)
	decrypted, err := encryptor.Decrypt(encrypted)
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf(`decrypted: %s`, decrypted)
}
