package main 

import (
	"fmt"
	"flag"
	"github.com/Apurer/eev/privateKey"
	"github.com/Apurer/eev/envVariable"
)

func main () {
	privkey, err := privateKey.Generate(privateKey.RSA, privateKey.Bits256)
	if err != nil {
		fmt.Println(err)
		return
	}

	envVariableName := "EEV"
	envVariableValue := "SuperSecret"

	err = envVariable.Set(envVariableName, envVariableValue, privkey)
	if err != nil {
		fmt.Println(err)
		return
	}

	envVariableDecrypted, err := envVariable.Get(envVariableName, privkey)
	if err != nil {
		fmt.Println(err)
		return
	}
	
	fmt.Println(envVariableDecrypted)
}