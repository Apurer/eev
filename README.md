# Encrypted Environment Variable
<a href="https://github.com/apurer/eev/actions"><img alt="GitHub Actions status" src="https://github.com/apurer/eev/workflows/Go/badge.svg"></a>

## Helpful code snippets

### Generate private key

```go
package main

import (
	"github.com/Apurer/eev/privatekey"
	"flag"
)

func main() {

	keytype := flag.String("type", "ECDSA", "path to save private key")
	keysize := flag.Int("size", 192, "size of pivate key in bits")
	keypath := flag.String("path", "./private-key", "path to save private key")
	alg := flag.String("alg", "AES192", "encryption algorithm by which private key is encrypted")
	passphrase := flag.String("passphrase", "", "passphrase by which private key is encrypted")
	flag.Parse()
		
	switch *keytype {
		case "RSA":
			*keytype = "RSA PRIVATE KEY"
		case "ECDSA":
			*keytype = "ECDSA PRIVATE KEY"
	}

	privkey, err := privatekey.Generate(*keytype, *keysize)
	if err != nil {
		panic(err)
	}

	encryptionAlg := privatekey.AES192

	switch *alg {
		case "AES128":
			encryptionAlg = privatekey.AES128
		case "AES192":
			encryptionAlg = privatekey.AES192
		case "AES256":
			encryptionAlg = privatekey.AES256
	}

	err = privatekey.Write(*keypath, privkey, *passphrase, encryptionAlg)

	if err != nil {
		panic(err)
	}
}
```
### Get encrypted value on output using specific private key

```go
package main

import (
	"github.com/Apurer/eev/privatekey"
	AES "github.com/Apurer/eev/aes"
	"flag"
	"fmt"
)

func main() {
	value := flag.String("value", "", "value to be encrypted")
	keypath := flag.String("key", "", "path to private key which is to be used for encryption of value")
	passphrase := flag.String("passphrase", "", "passphrase by which private key is encrypted")
	flag.Parse()

	privkey, err := privatekey.Read(*keypath, *passphrase)
	if err != nil {
		panic(err)
	}
	
	encrypted, err := AES.Encrypt(privkey, *value)
	if err != nil {
		panic(err)
	}

	fmt.Println(encrypted)
}
```
### Decrypt value using specific private key

```go
package main

import (
	"github.com/Apurer/eev/privatekey"
	AES "github.com/Apurer/eev/aes"
	"flag"
	"fmt"
)

func main() {
	value := flag.String("value", "", "value to be decrypted")
	keypath := flag.String("key", "", "path to private key which is to be used for decryption of value")
	passphrase := flag.String("passphrase", "", "passphrase by which private key is decrypted")
	flag.Parse()

	privkey, err := privatekey.Read(*keypath, *passphrase)
	if err != nil {
		panic(err)
	}
	
	decrypted, err := AES.Decrypt(privkey, *value)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(decrypted))
}
```
### Possible implementation in your program

```go
package main

import (
	"github.com/Apurer/eev/privatekey"
	"github.com/Apurer/eev"
	"flag"
)

func main() {

	key := flag.String("key", "", "path to private key which is to be used for dencryption of environment variable")
	passphrase := flag.String("passphrase", "", "passphrase by which private key is encrypted")
	flag.Parse()

	privkey, err = privatekey.Read(key, passphrase)
	if err != nil {
		panic(err)
	}

	API_KEY, err := eev.Get("API_KEY", privkey)
	if err != nil {
		panic(err)
	}
	
    url := "http://example.com"
	fmt.Println("URL: ", url)
	
    req, err := http.NewRequest("GET", url, nil)
    req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", API_KEY))

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    fmt.Println("response Status:", resp.Status)
    fmt.Println("response Headers:", resp.Header)
    body, _ := ioutil.ReadAll(resp.Body)
    fmt.Println("response Body:", string(body))
}
```