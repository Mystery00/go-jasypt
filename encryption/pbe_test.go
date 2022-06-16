package encryption

import (
	"go-jasypt/iv"
	"go-jasypt/salt"
	"testing"
)

func TestPBEWithMD5AndDES(t *testing.T) {
	encryptor := PBEWithMD5AndDES{config: EncryptorConfig{
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

	decrypt, err := encryptor.Decrypt(`oETK8sAv4XegRMrywC/hd7nBR0B0Ajka/MKLFoOuXMVGx78PG9jpRw==`)
	if err != nil {
		t.Error(err)
	}
	t.Log(decrypt)
}
