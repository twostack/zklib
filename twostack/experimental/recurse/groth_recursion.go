package recurse

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

type Sha256CircuitInner struct {
	RawTx []uints.U8

	//double-sha256 hash of the concatenation of above fields. Not reversed, so not quite a TxId
	CurrTxId []uints.U8 `gnark:",public"` //probably needs to provide the reversed version to save circuit space
}

/*
* Base case implementation
 */
func (circuit *Sha256CircuitInner) Define(api frontend.API) error {

	firstHash, err := calculateSha256(api, circuit.RawTx)
	if err != nil {
		return err
	}
	calculatedTxId, err := calculateSha256(api, firstHash)
	if err != nil {
		return err
	}

	//assert current public input matches calculated txId
	uapi, err := uints.New[uints.U32](api)
	for i := range circuit.CurrTxId {
		uapi.ByteAssertEq(circuit.CurrTxId[i], calculatedTxId[i])
	}

	return nil
}

/*
* General case to continue with proofs
 */
type Sha256CircuitOuter[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	PreviousProof   stdgroth16.Proof[G1El, G2El]
	PreviousVk      stdgroth16.VerifyingKey[G1El, G2El, GtEl] `gnark:"-"` // constant verification key
	PreviousWitness stdgroth16.Witness[FR]

	//CurrTxId []uints.U8 `gnark:",public"` //probably needs to provide the reversed version to save circuit space
}

func (circuit *Sha256CircuitOuter[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {

	verifier, err := stdgroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}

	err = verifier.AssertProof(circuit.PreviousVk, circuit.PreviousProof, circuit.PreviousWitness, stdgroth16.WithCompleteArithmetic())

	if err != nil {
		return err
	}

	return nil
}
func calculateSha256(api frontend.API, preImage []uints.U8) ([]uints.U8, error) {
	//instantiate a sha256 circuit
	sha256, err := sha2.New(api)

	if err != nil {
		return nil, err
	}

	//write the preimage into the circuit
	sha256.Write(preImage)

	//use the circuit directly to calculate the double-sha256 hash
	res := sha256.Sum()

	//assert that the circuit calculated correct hash length . Maybe not needed.
	if len(res) != 32 {
		return nil, fmt.Errorf("not 32 bytes")
	}
	return res, nil
}
