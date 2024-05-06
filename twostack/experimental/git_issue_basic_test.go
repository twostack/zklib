package experimental

/**
NOTE: This code is taken (and modified) from a reported Github issue on the gnark board.

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
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

type innerCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *innerCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, c.Y)

	return nil
}

// outerCircuit is the generic outer circuit which can verify Groth16 proofs
// using field emulation or 2-chains of curves.
type outerCircuitGI[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        stdgroth16.Proof[G1El, G2El]
	VerifyingKey stdgroth16.VerifyingKey[G1El, G2El, GtEl]
	InnerWitness stdgroth16.Witness[FR]
}

func (c *outerCircuitGI[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	err = verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
	return err
}

func getInnerBasicCircuit(field *big.Int, xVal int, yVal int) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof, error) {
	//make the compiler happy
	circuit := innerCircuit{}

	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	innerPK, innerVK, err := groth16.Setup(innerCcs)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// inner proof
	innerAssignment := &innerCircuit{
		X: xVal,
		Y: yVal,
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

func TestRecursiveCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	innerCcs, innerVK, innerPubWitness, innerProof, err := getInnerBasicCircuit(ecc.BLS12_377.ScalarField(), 5, 5)
	assert.NoError(err)
	// initialize the witness elements
	circuitVk, err := stdgroth16.ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVK)
	assert.NoError(err)
	circuitPubWitness, err := stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](innerPubWitness)
	fmt.Printf("nbInnerPubWitness:%v, witness:%v\n", len(circuitPubWitness.Public), circuitPubWitness.Public)

	assert.NoError(err)
	circuitProof, err := stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	assert.NoError(err)

	outerAssignment := &outerCircuitGI[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitPubWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}

	// the witness size depends on the number of public variables. We use the
	// compiled inner circuit to deduce the required size for the outer witness
	// using functions [stdgroth16.PlaceholderWitness] and
	// [stdgroth16.PlaceholderVerifyingKey]
	outerCircuit := &outerCircuitGI[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
		Proof:        stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerCcs),
		VerifyingKey: stdgroth16.PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerCcs),
	}

	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField())
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
