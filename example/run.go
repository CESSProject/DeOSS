package main

import (
	"fmt"

	"github.com/CESSProject/DeOSS/node"
)

func main() {
	n := node.New()
	pk, err := n.VerifyAccountSignature("cXh5StobuVP4B7mGH9xn8dSsDtXks4qLAou8ZdkZ6DbB6zzxe", "<Bytes>timestemp1708566687367</Bytes>", "fe98b9f492ee94c0fdf5b3fef5b72555683a9747b744c360863e2a2b22560418b2c1b9d9d158553afd3005c07291484b59d1c72ee70cfbb8440106de5fd8b18b")
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("ok: ", pk)
	}
	//n.Run2(8080, "")
}
