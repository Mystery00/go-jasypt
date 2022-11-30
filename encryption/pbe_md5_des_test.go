package encryption

import (
	"github.com/Mystery00/go-jasypt/iv"
	"github.com/Mystery00/go-jasypt/salt"
	"testing"
)

func TestPBEWithMD5AndDES(t *testing.T) {
	encryptor := NewPBEWithMD5AndDES(EncryptorConfig{
		Password:      "password",
		SaltGenerator: salt.RandomSaltGenerator{},
		IvGenerator:   iv.RandomIvGenerator{},
	})
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
	t.Logf(`decrypted: [%s]`, decrypted)
}
