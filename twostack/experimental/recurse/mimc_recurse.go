/***
NOTICE : UNTESTED !!!!!
*/

package recurse

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/std/recursion/plonk"
)

type MimcCircuitBase struct {
	X frontend.Variable
	Y frontend.Variable
	Z frontend.Variable `gnark:",public"`
}

func (circuit *MimcCircuitBase) Define(api frontend.API) error {
	z := api.Mul(circuit.X, circuit.Y)

	api.AssertIsEqual(circuit.Z, z)

	return nil
}

type MimcCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	PreviousProof   stdgroth16.Proof[G1El, G2El]
	PreviousVk      stdgroth16.VerifyingKey[G1El, G2El, GtEl]
	PreviousWitness stdgroth16.Witness[FR]

	X frontend.Variable
	Y frontend.Variable
	Z frontend.Variable `gnark:",public"`
}

type MimcPlonkCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	PreviousProof   plonk.Proof[FR, G1El, G2El]
	PreviousVk      plonk.VerifyingKey[FR, G1El, G2El]
	PreviousWitness plonk.Witness[FR]

	X frontend.Variable
	Y frontend.Variable
	Z frontend.Variable `gnark:",public"`
}

func (circuit *MimcCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {

	verifier, err := stdgroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}

	err = verifier.AssertProof(circuit.PreviousVk, circuit.PreviousProof, circuit.PreviousWitness, stdgroth16.WithCompleteArithmetic())

	if err != nil {
		return err
	}

	z := api.Mul(circuit.X, circuit.Y)
	api.AssertIsEqual(circuit.Z, z)

	return nil
}
func (circuit *MimcPlonkCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {

	verifier, err := plonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}

	err = verifier.AssertProof(circuit.PreviousVk, circuit.PreviousProof, circuit.PreviousWitness, plonk.WithCompleteArithmetic())

	if err != nil {
		return err
	}

	z := api.Mul(circuit.X, circuit.Y)
	api.AssertIsEqual(circuit.Z, z)

	return nil
}
