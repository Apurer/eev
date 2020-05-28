package envVariable

import (
	"github.com/Apurer/eev/AES"
	"errors"
	"os"
)

func Get(name string, key []byte) (value string, err error) {
	value = os.Getenv(name)
	if value == "" {
		return value, errors.New("environment variable is not set or is empty")
	}

	decrypted, err := AES.Decrypt(key, value)
	if err != nil {
		return value, err
	}

	return string(decrypted), err
}

func Set(name string, content string, key []byte) (err error) {

	encrypted, err := AES.Encrypt(key, content)
	if err != nil {
		return err
	}
	err = os.Setenv(name, encrypted)

	return err
}
