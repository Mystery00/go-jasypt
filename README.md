# go-jasypt

GoLang implements jasypt encryption and decryption

# How to use

1. you need to import jasypt package:

```shell
go get -u github.com/Mystery00/go-jasypt
```

2. use like this:

```go
package jasypt

import (
	"github.com/Mystery00/go-jasypt"
	"github.com/Mystery00/go-jasypt/iv"
	"github.com/Mystery00/go-jasypt/salt"
)

const (
	// specify the algorithm
	algorithm = "PBEWithHMACSHA512AndAES_256"
	// specify the password
	password = "password"
)

func Encrypt(message string) (string, error) {
	// create a new instance of jasypt
	encryptor := jasypt.New(algorithm, jasypt.NewConfig(
		jasypt.SetPassword(password),
		jasypt.SetSaltGenerator(salt.RandomSaltGenerator{}),
		jasypt.SetIvGenerator(iv.RandomIvGenerator{}),
	))
	// encrypt the message
	return encryptor.Encrypt(message)
}

func Decrypt(encode string) (string, error) {
	// create a new instance of jasypt
	encryptor := jasypt.New(algorithm, jasypt.NewConfig(
		jasypt.SetPassword(password),
		jasypt.SetSaltGenerator(salt.RandomSaltGenerator{}),
		jasypt.SetIvGenerator(iv.RandomIvGenerator{}),
	))
	// decrypt the message
	return encryptor.Decrypt(encode)
}
```