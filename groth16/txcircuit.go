package groth16

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
	"math/big"
)

// export
type Sha256Circuit struct {
	//PreImage frontend.Variable
	PreImage [9]uints.U8 `gnark:",public"`
	//Hash     frontend.Variable `gnark:",public"`
	Hash [32]uints.U8 `gnark:",public"`
}

// https://pkg.go.dev/github.com/consensys/gnark/backend/hint#Function
func sha256Hint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {

	return nil
}

// Define
// A simple circuit for generating a proof that attests that the
// prover knows the pre-image to a sha256 hash
func (circuit *Sha256Circuit) Define(api frontend.API) error {

	//instantiate a sha256 circuit
	sha256, _ := sha2.New(api)

	//b, _ := api.Compiler().NewHint(sha256Hint, 1, circuit.PreImage)
	//fmt.Println(b[0]) // should contain the calculated hash of PreImage

	//write the preimage into the circuit
	sha256.Write(circuit.PreImage[:])

	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	//use the circuit directly to calculate the sha256 hash
	res := sha256.Sum()

	//assert that the circuit calculated correct hash length . Maybe not needed.
	if len(res) != 32 {
		return fmt.Errorf("not 32 bytes")
	}

	//loop over the individual bytes of the calculated hash
	//and compare them to the expected digest
	for i := range circuit.Hash {
		uapi.ByteAssertEq(circuit.Hash[i], res[i])
	}

	return nil
}
