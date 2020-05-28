package AES

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"crypto/cipher"
	"encoding/base64"
	"io"
	"errors"
	"fmt"
	"github.com/Apurer/eev/privateKey"
)
// remove passphrase from here and decryption of pem
func Encrypt(key []byte, content string) (encrypted string, err error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return encrypted, errors.New("decoded pem block is empty")
	}

	switch keyType := block.Type; keyType {
	case privateKey.RSA:
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return encrypted, err
		}
		// generate a new aes cipher using our 32 byte long key
		// AES-128, AES-192, or AES-256.
		ciph, err := aes.NewCipher(priv.D.Bytes())
		gcm, err := cipher.NewGCM(ciph)
		if err != nil {
			return encrypted, err
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
			return encrypted, err
		}
		
		return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(content), nil)), err
	case privateKey.ECDSA:
		priv, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return encrypted, err
		}
		// generate a new aes cipher using our 32 byte long key
		// AES-128, AES-192, or AES-256.
		ciph, err := aes.NewCipher(priv.D.Bytes())
		gcm, err := cipher.NewGCM(ciph)
		if err != nil {
			return encrypted, err
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
			return encrypted, err
		}

		return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(content), nil)), err
	default:
		return encrypted, errors.New(fmt.Sprintf("private key type: %s is not supported", keyType))
	}
}
// remove passphrase from here and decryption of pem
func Decrypt(key []byte, content string) (decrypted []byte, err error) {
	data, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return decrypted, err
	}
	block, _ := pem.Decode(key)
	if block == nil {
		return decrypted, err
	}

	switch keyType := block.Type; keyType {
	case privateKey.RSA:
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return decrypted, err
		}
		ciph, err := aes.NewCipher(priv.D.Bytes())
		gcm, err := cipher.NewGCM(ciph)
		if err != nil {
			return decrypted, err
		}
		nonceSize := gcm.NonceSize()
		if len(data) < nonceSize {
			return decrypted, errors.New("encrypted text is smaller than nonce size")
		}
	
		nonce, cipherText := data[:nonceSize], data[nonceSize:]
		decrypted, err = gcm.Open(nil, nonce, cipherText, nil)
		if err != nil {
			return decrypted, err
		}
	
		return decrypted, err
	case privateKey.ECDSA:
		priv, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return decrypted, err
		}
		ciph, err := aes.NewCipher(priv.D.Bytes())
		gcm, err := cipher.NewGCM(ciph)
		if err != nil {
			return decrypted, err
		}
		nonceSize := gcm.NonceSize()
		if len(data) < nonceSize {
			return decrypted, errors.New("encrypted text is smaller than nonce size")
		}
		
		nonce, cipherText := data[:nonceSize], data[nonceSize:]
		decrypted, err = gcm.Open(nil, nonce, cipherText, nil)
		if err != nil {
			return decrypted, err
		}
	
		return decrypted, err
	default:
		return decrypted, errors.New(fmt.Sprintf("private key type: %s is not supported", keyType))
	}
}
