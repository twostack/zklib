package recurse

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

type Sha256CircuitInner[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	RawTx []uints.U8

	//double-sha256 hash of the concatenation of above fields. Not reversed, so not quite a TxId
	CurrTxId [32]uints.U8 `gnark:",public"` //probably needs to provide the reversed version to save circuit space
}

/*
* Base case implementation
 */
func (circuit *Sha256CircuitInner[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {

	//api.AssertIsEqual(len(circuit.RawTx), 191)

	return nil
}

/*
* General case to continue with proofs
 */
type Sha256CircuitOuter[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	PreviousProof   stdgroth16.Proof[G1El, G2El]
	PreviousVk      stdgroth16.VerifyingKey[G1El, G2El, GtEl] `gnark:"-"` // constant verification key
	PreviousWitness stdgroth16.Witness[FR]

	CurrTxId [32]uints.U8 `gnark:",public"` //probably needs to provide the reversed version to save circuit space
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
