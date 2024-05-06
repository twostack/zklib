package experimental

/**
NOTE: This code is taken from a reported Github issue on the gnark board.

Reproduced here for internal testing and verification.

https://github.com/Consensys/gnark/issues/1079


This test fails at the end of the in-circuit proof verifier. It attempts
to match pairings, and fails.

Error at --- > std/recursion/groth16/verifier.go : line 665

Currently fails :
    git_issue_sha256_mod_test.go:199:
        	Error Trace:	/Users/stephanfebruary/IdeaProjects/zklib/twostack/experimental/git_issue_sha256_mod_test.go:199
        	Error:      	Received unexpected error:
        	            	[assertIsEqual] 246911385926790084676521132327533278724172104698513407034219432829442646692225982363073196559508426744023449281697 == 178019439188757268520945169744054423925444462796904837538274209893135190916488394525540979064023104574358501473579
        	            	fields_bls12377.(*E2).AssertIsEqual
        	            		e2.go:196

At end of AssertProof() method it fails to match the pairings
*/
import (
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

var innerCurve = ecc.BLS12_377
var outerCurve = ecc.BW6_761

type scalarField = sw_bls12377.ScalarField
type g1Affine = sw_bls12377.G1Affine
type g2Affine = sw_bls12377.G2Affine
type gTEl = sw_bls12377.GT

//var innerCurve = ecc.BN254
//var outerCurve = ecc.BN254
//
//type scalarField = sw_bn254.ScalarField
//type g1Affine = sw_bn254.G1Affine
//type g2Affine = sw_bn254.G2Affine
//type gTEl = sw_bn254.GTEl

type InnerHashCircuit struct {
	Input  []uints.U8
	Output [32]uints.U8 `gnark:",public"`
}

func (c *InnerHashCircuit) Define(api frontend.API) error {
	h, err := sha2.New(api)
	if err != nil {
		return fmt.Errorf("new sha2: %w", err)
	}
	h.Write(c.Input[:])
	res := h.Sum()
	if len(res) != len(c.Output) {
		return fmt.Errorf("wrong digest size")
	}
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return fmt.Errorf("new uints api: %w", err)
	}
	for i := range res {
		uapi.ByteAssertEq(res[i], c.Output[i])
	}
	return nil
}

// OuterCircuit is the generic outer circuit which can verify Groth16 proofs
// using field emulation or 2-chains of curves.
type OuterCircuitGI[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        stdgroth16.Proof[G1El, G2El]
	VerifyingKey stdgroth16.VerifyingKey[G1El, G2El, GtEl]
	InnerWitness stdgroth16.Witness[FR]
}

func (c *OuterCircuitGI[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	//curve, err := algebra.GetCurve[FR, G1El](api)
	//if err != nil {
	//	return fmt.Errorf("new curve: %w", err)
	//}
	//pairing, err := algebra.GetPairing[G1El, G2El, GtEl](api)
	//if err != nil {
	//	return fmt.Errorf("get pairing: %w", err)
	//}
	verifier, err := stdgroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	err = verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
	return err
}

func getInnerHashCircuit(field *big.Int, input []uints.U8, output [32]uints.U8) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof, error) {
	//make the compiler happy
	circuit := InnerHashCircuit{
		Input: make([]uints.U8, len(input)),
	}

	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	innerPK, innerVK, err := groth16.Setup(innerCcs)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// inner proof
	innerAssignment := &InnerHashCircuit{
		Input:  input,
		Output: output,
	}
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	innerProof, err := groth16.Prove(innerCcs, innerPK, innerWitness)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	err = groth16.Verify(innerProof, innerVK, innerPubWitness)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return innerCcs, innerVK, innerPubWitness, innerProof, nil
}

func TestRecursiveHashCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	msg := []byte("hello, world")
	input := uints.NewU8Array(msg)
	digest := sha256.Sum256(msg)

	var output [32]uints.U8
	for i := range digest {
		output[i] = uints.NewU8(digest[i])
	}

	innerCcs, innerVK, innerPubWitness, innerProof, err := getInnerHashCircuit(innerCurve.ScalarField(), input, output)
	assert.NoError(err)
	// initialize the witness elements
	circuitVk, err := stdgroth16.ValueOfVerifyingKey[g1Affine, g2Affine, gTEl](innerVK)
	assert.NoError(err)
	circuitPubWitness, err := stdgroth16.ValueOfWitness[scalarField](innerPubWitness)
	fmt.Printf("nbInnerPubWitness:%v, witness:%v\n", len(circuitPubWitness.Public), circuitPubWitness.Public)

	assert.NoError(err)
	circuitProof, err := stdgroth16.ValueOfProof[g1Affine, g2Affine](innerProof)
	assert.NoError(err)

	outerAssignment := &OuterCircuitGI[scalarField, g1Affine, g2Affine, gTEl]{
		InnerWitness: circuitPubWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}

	// the witness size depends on the number of public variables. We use the
	// compiled inner circuit to deduce the required size for the outer witness
	// using functions [stdgroth16.PlaceholderWitness] and
	// [stdgroth16.PlaceholderVerifyingKey]
	outerCircuit := &OuterCircuitGI[scalarField, g1Affine, g2Affine, gTEl]{
		InnerWitness: stdgroth16.PlaceholderWitness[scalarField](innerCcs),
		Proof:        stdgroth16.PlaceholderProof[g1Affine, g2Affine](innerCcs),
		VerifyingKey: stdgroth16.PlaceholderVerifyingKey[g1Affine, g2Affine, gTEl](innerCcs),
	}

	err = test.IsSolved(outerCircuit, outerAssignment, outerCurve.ScalarField())
	assert.NoError(err)

	//// compile the outer circuit
	//outerCcs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, outerCircuit)
	//assert.NoError(err)
	//// create prover witness from the assignment
	//outerWitness, err := frontend.NewWitness(outerAssignment, ecc.BW6_761.ScalarField())
	//assert.NoError(err)

	//// create public witness from the assignment
	//outerPublicWitness, err := outerWitness.Public()
	//assert.NoError(err)

	//// create Groth16 setup. NB! UNSAFE
	//outerPk, outerVk, err := groth16.Setup(outerCcs) // UNSAFE! Use MPC
	//assert.NoError(err)
	//
	//// construct the groth16 proof of verifying Groth16 proof in-circuit
	//outerProof, err := groth16.Prove(outerCcs, outerPk, outerWitness)
	//assert.NoError(err)
	//
	//// verify the Groth16 proof
	//err = groth16.Verify(outerProof, outerVk, outerPublicWitness)
	//assert.NoError(err)

}
