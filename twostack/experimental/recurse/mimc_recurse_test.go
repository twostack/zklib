package recurse

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
	"time"
)

var innerCurve = ecc.BN254
var outerCurve = ecc.BN254

type scalarField = sw_bn254.ScalarField
type g1Affine = sw_bn254.G1Affine
type g2Affine = sw_bn254.G2Affine
type gTEl = sw_bn254.GTEl

// var innerCurve = ecc.BLS12_377
// var outerCurve = ecc.BW6_761
//
// type scalarField = sw_bls12377.ScalarField
// type g1Affine = sw_bls12377.G1Affine
// type g2Affine = sw_bls12377.G2Affine
// type gTEl = sw_bls12377.GT
//
// //
//
// var innerCurve2 = ecc.BW6_761
// var outerCurve2 = ecc.BLS12_377
//
// type scalarField2 = sw_bw6761.ScalarField
// type g1Affine2 = sw_bw6761.G1Affine
// type g2Affine2 = sw_bw6761.G2Affine
// type gTEl2 = sw_bw6761.GTEl
func TestMimcBaseCase(t *testing.T) {

}

// Test that we can recursively verify the base proof
func TestMimcNormalCase(t *testing.T) {

}

// Test that we can recursively verify a normal proof
func TestMimcNormal2(t *testing.T) {

}

func getInnerBaseCircuit2(t *testing.T, field *big.Int, outerPubWitness witness.Witness, outerProof groth16.Proof, outerCcs constraint.ConstraintSystem) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof, error) {

	assert := test.NewAssert(t)
	//make the compiler happy
	circuit := &MimcCircuit[scalarField, g1Affine, g2Affine, gTEl]{
		PreviousWitness: stdgroth16.PlaceholderWitness[scalarField](outerCcs),
		PreviousProof:   stdgroth16.PlaceholderProof[g1Affine, g2Affine](outerCcs),
		PreviousVk:      stdgroth16.PlaceholderVerifyingKey[g1Affine, g2Affine, gTEl](outerCcs),
	}

	start := time.Now()
	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, circuit)
	assert.NoError(err)
	elapsed := time.Since(start)
	fmt.Printf("Compilation over emulated field took %s\n", elapsed)

	start = time.Now()
	innerPK, innerVK, err := groth16.Setup(innerCcs)
	assert.NoError(err)
	elapsed = time.Since(start)
	fmt.Printf("Setup over emulated field took %s\n", elapsed)

	circuitVk, err := stdgroth16.ValueOfVerifyingKey[g1Affine, g2Affine, gTEl](innerVK)
	assert.NoError(err)
	circuitPubWitness, err := stdgroth16.ValueOfWitness[scalarField](outerPubWitness)
	//fmt.Printf("nbInnerPubWitness:%v, witness:%v\n", len(circuitPubWitness.Public), circuitPubWitness.Public)

	assert.NoError(err)
	circuitProof, err := stdgroth16.ValueOfProof[g1Affine, g2Affine](outerProof)
	assert.NoError(err)

	outerAssignment := &MimcCircuit[scalarField, g1Affine, g2Affine, gTEl]{
		PreviousWitness: circuitPubWitness,
		PreviousProof:   circuitProof,
		PreviousVk:      circuitVk,
		X:               2,
		Y:               3,
		Z:               6,
	}

	//our new inner witness is based on previous OuterWitness /Assignment
	innerWitness, err := frontend.NewWitness(outerAssignment, field)
	assert.NoError(err)

	//generate our new proof to recursively verify our previous outerproof
	innerProof, err := groth16.Prove(innerCcs, innerPK, innerWitness)
	assert.NoError(err)

	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)

	//Verify our new proof
	err = groth16.Verify(innerProof, innerVK, innerPubWitness)
	assert.NoError(err)

	return innerCcs, innerVK, innerPubWitness, innerProof, nil
}

func getInnerBaseCircuit(field *big.Int) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof, error) {
	//make the compiler happy
	circuit := MimcCircuitBase{}

	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	innerPK, innerVK, err := groth16.Setup(innerCcs)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// inner proof
	innerAssignment := &MimcCircuitBase{
		X: 2,
		Y: 3,
		Z: 6,
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

	innerCcs, innerVK, innerPubWitness, innerProof, err := getInnerBaseCircuit(innerCurve.ScalarField())
	assert.NoError(err)
	// initialize the witness elements
	circuitVk, err := stdgroth16.ValueOfVerifyingKey[g1Affine, g2Affine, gTEl](innerVK)
	assert.NoError(err)
	circuitPubWitness, err := stdgroth16.ValueOfWitness[scalarField](innerPubWitness)
	fmt.Printf("nbInnerPubWitness:%v, witness:%v\n", len(circuitPubWitness.Public), circuitPubWitness.Public)

	assert.NoError(err)
	circuitProof, err := stdgroth16.ValueOfProof[g1Affine, g2Affine](innerProof)
	assert.NoError(err)

	outerAssignment := &MimcCircuit[scalarField, g1Affine, g2Affine, gTEl]{
		PreviousWitness: circuitPubWitness,
		PreviousProof:   circuitProof,
		PreviousVk:      circuitVk,
		X:               2,
		Y:               3,
		Z:               6,
	}

	outerCircuit := &MimcCircuit[scalarField, g1Affine, g2Affine, gTEl]{
		PreviousWitness: stdgroth16.PlaceholderWitness[scalarField](innerCcs),
		PreviousProof:   stdgroth16.PlaceholderProof[g1Affine, g2Affine](innerCcs),
		PreviousVk:      stdgroth16.PlaceholderVerifyingKey[g1Affine, g2Affine, gTEl](innerCcs),
	}

	err = test.IsSolved(outerCircuit, outerAssignment, outerCurve.ScalarField())
	assert.NoError(err)

	//// compile the outer circuit
	outerCcs, err := frontend.Compile(outerCurve.ScalarField(), r1cs.NewBuilder, outerCircuit)
	//assert.NoError(err)
	//// create prover witness from the assignment
	outerWitness, err := frontend.NewWitness(outerAssignment, outerCurve.ScalarField())
	//assert.NoError(err)

	//// create public witness from the assignment
	outerPublicWitness, err := outerWitness.Public()
	assert.NoError(err)

	//// create Groth16 setup. NB! UNSAFE
	outerPk, outerVk, err := groth16.Setup(outerCcs) // UNSAFE! Use MPC
	assert.NoError(err)
	//
	//// construct the groth16 proof of verifying Groth16 proof in-circuit
	outerProof, err := groth16.Prove(outerCcs, outerPk, outerWitness)
	assert.NoError(err)
	//
	//// verify the Groth16 proof
	err = groth16.Verify(outerProof, outerVk, outerPublicWitness)
	assert.NoError(err)

	//do next round of proving a new normal proof from previous normal proof
	//innerNormalCcs, innerNormalVK, innerNormalPubWitness, innerNormalProof, err :=  getInnerNormalCircuit(t, innerCurve.ScalarField(), outerCcs, outerPk, outerPublicWitness, outerProof, outerVk)
	//_, _, err = getInnerNormalCircuit(t, innerCurve.ScalarField(), innerNormalCcs, innerNormalPk, newPubInnerWitness, outerProof, innerNormalVK)
	//assert.NoError(err)

	getInnerBaseCircuit2(t, innerCurve.ScalarField(), outerPublicWitness, outerProof, outerCcs)

}

func getInnerNormalCircuit(t *testing.T, field *big.Int, innerCcs constraint.ConstraintSystem, prevPk groth16.ProvingKey, prevWitness witness.Witness, prevProof groth16.Proof, prevVk groth16.VerifyingKey) (witness.Witness, groth16.Proof, error) {
	assert := test.NewAssert(t)

	circuitPubWitness, err := stdgroth16.ValueOfWitness[scalarField](prevWitness)
	assert.NoError(err)
	fmt.Printf("nbInnerPubWitness:%v, witness:%v\n", len(circuitPubWitness.Public), circuitPubWitness.Public)
	circuitVk, err := stdgroth16.ValueOfVerifyingKey[g1Affine, g2Affine, gTEl](prevVk)
	assert.NoError(err)

	circuitProof, err := stdgroth16.ValueOfProof[g1Affine, g2Affine](prevProof)
	assert.NoError(err)

	innerAssignment := &MimcCircuit[scalarField, g1Affine, g2Affine, gTEl]{
		PreviousWitness: circuitPubWitness,
		PreviousProof:   circuitProof,
		PreviousVk:      circuitVk,
		X:               2,
		Y:               3,
		Z:               6,
	}

	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	if err != nil {
		return nil, nil, err
	}
	innerProof, err := groth16.Prove(innerCcs, prevPk, innerWitness)
	if err != nil {
		return nil, nil, err
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		return nil, nil, err
	}
	err = groth16.Verify(innerProof, prevVk, innerPubWitness)
	if err != nil {
		return nil, nil, err
	}

	return innerPubWitness, innerProof, nil
}

func getParams(innerField *big.Int, innerCcs constraint.ConstraintSystem) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {

	circuit := &MimcCircuit[scalarField, g1Affine, g2Affine, gTEl]{
		PreviousWitness: stdgroth16.PlaceholderWitness[scalarField](innerCcs),
		PreviousProof:   stdgroth16.PlaceholderProof[g1Affine, g2Affine](innerCcs),
		PreviousVk:      stdgroth16.PlaceholderVerifyingKey[g1Affine, g2Affine, gTEl](innerCcs),
	}

	innerNormalCcs, err := frontend.Compile(innerField, r1cs.NewBuilder, circuit)
	if err != nil {
		return nil, nil, nil, err
	}

	innerPK, innerVK, err := groth16.Setup(innerCcs)
	if err != nil {
		return nil, nil, nil, err
	}

	return innerNormalCcs, innerPK, innerVK, nil
}
