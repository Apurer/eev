package privateKey

import (
	"crypto/rsa"
	"encoding/pem"
	"crypto/elliptic"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"io/ioutil"
	"errors"
	"fmt"
)

const (
	RSA     = "RSA PRIVATE KEY"
	ECDSA   = "ECDSA PRIVATE KEY"
	Bits128 = 128
	Bits192 = 192
	Bits256 = 256
	AES128  = x509.PEMCipherAES128
	AES192  = x509.PEMCipherAES192
	AES256  = x509.PEMCipherAES256
	NoPassphrase = ""
	NoEncryptionAlgorithm = 0
)

type Info struct {
	Id string
	Type string
	Size string
	Path string
}

func Generate(keyType string, keySize int) (key []byte, err error) {
	switch keyType {
	case RSA:
		{
			switch keySize {
			case Bits128, Bits192, Bits256:
				privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
                if err != nil {
					return key, err
                }
				block := &pem.Block{
					Type:  keyType,
					Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
				}
				
				return pem.EncodeToMemory(block), nil

			default:
				return key, errors.New(fmt.Sprintf("private key size: %d is not supported", keySize))
			}
		}
	case ECDSA:
		{
			switch keySize {
			case Bits256:
				privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					return key, err
                }
				x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
                if err != nil {
					return key, err
                }
				block := &pem.Block{
					Type:  "ECDSA PRIVATE KEY",
					Bytes: x509Encoded,
				}
				
				return pem.EncodeToMemory(block), nil
			default:
				return key, errors.New(fmt.Sprintf("private key size: %d is not supported for %s", keySize, keyType))
			}
		}
	default:
		return key, errors.New(fmt.Sprintf("private key type: %s is not supported", keyType))
	}
}

func Read(path string, passphrase string) (key []byte, err error) {
	// make change so it turns encrypted pem into normal pem
	key, err = ioutil.ReadFile(path)
	if err != nil {
		return key, err
	}
	block, _ := pem.Decode(key)
	if x509.IsEncryptedPEMBlock(block) {
		block, _ := pem.Decode(key)
		if block == nil {
			return key, errors.New("decoded pem block is empty")
		}
		block.Bytes, err = x509.DecryptPEMBlock(block, []byte(passphrase))
		key = pem.EncodeToMemory(block)
	}

	return key, nil
}

func Write(path string, key []byte, passphrase string, encryptionAlg x509.PEMCipher) (err error) {
	if passphrase != NoPassphrase && encryptionAlg != NoEncryptionAlgorithm {
		block, _ := pem.Decode(key)
		if block == nil {
			return errors.New("decoded pem block is empty")
		}
		block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(passphrase), encryptionAlg)
		if err != nil {
			return err
		}
		key = pem.EncodeToMemory(block)
	} 
	err = ioutil.WriteFile(path, key, 0600)
	if err != nil {
	  return err
	}
	return nil
}