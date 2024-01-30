package groth16

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

type HashChainCircuit struct {
	//PreImage frontend.Variable
	PreImage [9]uints.U8 `gnark:",public"`
	//Hash     frontend.Variable `gnark:",public"`
	Hash [32]uints.U8 `gnark:",public"`
}

/*
*

	A Circuit that proves that the current TxId has been properly accumulated
	into a hashchain.
*/
func (circuit *HashChainCircuit) Define(api frontend.API) error {

	//instantiate sha256 in-circuit
	sha256, _ := sha2.New(api)

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

	//

	return nil
}
