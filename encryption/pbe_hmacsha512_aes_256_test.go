package encryption

import (
	"github.com/Mystery00/go-jasypt/iv"
	"github.com/Mystery00/go-jasypt/salt"
	"testing"
)

func TestPBEWithHMACSHA512AndAES_256(t *testing.T) {
	encryptor := NewPBEWithHMACSHA512AndAES_256(EncryptorConfig{
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
	decrypted1, err := encryptor.Decrypt("yBC5Tt8PFp+mIoxY69zYfW2f/wxV6ofYMuHGIxd8fxMra/riH78DyMz4zNTCcQ9z")
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf(`decrypted1: [%s]`, decrypted1)
	if decrypted1 != `1234567890` {
		t.Error(`decrypted1 not equal to 1234567890`)
	}
}
