package twostack

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/groth16"
)

type SigCircuitBaseCase[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	//private params
	TxPreImage [128]uints.U8

	//public params
	//double-sha256 hash of the concatenation of above fields. Not reversed, so not quite a TxId
	ImageHash [32]uints.U8 `gnark:",public"` //shahash of the scriptPubkey. Preserve between IVC rounds.
}

func (circuit *SigCircuitBaseCase[FR, G1El, G2El, GTEl]) Define(api frontend.API) error {

	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	//instantiate a sha256 circuit
	sha256, err := sha2.New(api)

	if err != nil {
		return err
	}

	//write the preimage into the circuit
	sha256.Write(circuit.TxPreImage[:])

	//use the circuit directly to calculate the double-sha256 hash
	res := sha256.Sum()

	//assert that currTxId == TokenId
	for i := range circuit.ImageHash {
		uapi.ByteAssertEq(circuit.ImageHash[i], res[i])
	}

	return nil
}

// [FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT]
type SigCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	PreviousProof   groth16.Proof[G1El, G2El]
	PreviousVk      groth16.VerifyingKey[G1El, G2El, GtEl] `gnark:"-"` // constant verification key
	PreviousWitness groth16.Witness[FR]

	//private params
	TxPreImage [128]uints.U8
	ImageHash  [32]uints.U8 `gnark:",public"` //public input for proof verification
}

func (circuit *SigCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {

	/**
	Following section of code is copied from the nonnative_doc_test.go example
	*/
	verifier, err := groth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	verifier.AssertProof(circuit.PreviousVk, circuit.PreviousProof, circuit.PreviousWitness)
	//if err != nil {
	//	return fmt.Errorf("new verifier: %w", err)
	//}

	/*
	  It would be sufficient to assert that the value of
	  circuit.PreviousWitness.Public must == circuit.PrevTxId
	*/

	//publicInputs := []frontend.Variable{circuit.ImageHash}

	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	//instantiate a sha256 circuit
	sha256, err := sha2.New(api)

	if err != nil {
		return err
	}

	//write the preimage into the circuit
	sha256.Write(circuit.TxPreImage[:])

	//use the circuit directly to calculate the double-sha256 hash
	res := sha256.Sum()

	//assert that currTxId == TokenId
	for i := range circuit.ImageHash {
		uapi.ByteAssertEq(circuit.ImageHash[i], res[i])
	}

	return nil
}
