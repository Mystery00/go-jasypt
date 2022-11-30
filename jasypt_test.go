package jasypt

import (
	"github.com/Mystery00/go-jasypt/iv"
	"github.com/Mystery00/go-jasypt/salt"
	"testing"
)

func TestJasypt(t *testing.T) {
	config := NewConfig(SetPassword("password"), SetSaltGenerator(salt.RandomSaltGenerator{}), SetIvGenerator(iv.RandomIvGenerator{}))
	encryptor := New("PBEWithHMACSHA512AndAES_256", config)
	encrypt, err := encryptor.Encrypt(`plain text`)
	if err != nil {
		t.Error(err)
	}
	decrypt, err := encryptor.Decrypt(encrypt)
	if err != nil {
		t.Error(err)
	}
	if decrypt != `plain text` {
		t.Error(`decrypt failed`)
	}
	decrypted1, err := encryptor.Decrypt("yBC5Tt8PFp+mIoxY69zYfW2f/wxV6ofYMuHGIxd8fxMra/riH78DyMz4zNTCcQ9z")
	if err != nil {
		t.Error(err)
		return
	}
	if decrypted1 != `1234567890` {
		t.Error(`decrypted1 not equal to 1234567890`)
	}
}
