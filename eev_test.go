package eev

import (
	"github.com/Apurer/eev/privateKey"
	"testing"
)

func TestFunctions(t *testing.T) {

	privkey, err := privateKey.Generate(privateKey.RSA, privateKey.Bits256)
	if err != nil {
		t.Errorf("error during generating private key function occured with message: %q", err)
	}

	err = privateKey.Write("./private-key", privkey, privateKey.NoPassphrase, privateKey.NoEncryptionAlgorithm)
	if err != nil {
		t.Errorf("error during writting private key function occured with message: %q", err)
	}
	privkey, err = privateKey.Read("./private-key", privateKey.NoPassphrase)
	if err != nil {
		t.Errorf("error during reading private key function occured with message: %q", err)
	}

	envVariableName := "EEV"
	envVariableValue := "SuperSecret"

	err = Set(envVariableName, envVariableValue, privkey)
	if err != nil {
		t.Errorf("error during setting environment variable function occured with message: %q", err)
	}

	envVariableDecrypted, err := Get(envVariableName, privkey)
	if err != nil {
		t.Errorf("error during getting environment variable function occured with message: %q", err)
	}

    got := envVariableDecrypted
    want := envVariableValue

    if got != want {
        t.Errorf("got %q want %q", got, want)
    }
}