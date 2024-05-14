package recurse

import (
	"fmt"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
	"math/big"
	"testing"
	"time"
)

//var innerCurve = ecc.BN254
//var outerCurve = ecc.BN254
//
//type scalarField = sw_bn254.ScalarField
//type g1Affine = sw_bn254.G1Affine
//type g2Affine = sw_bn254.G2Affine
//type gTEl = sw_bn254.GTEl

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
func TestMimcPlonkBaseCase(t *testing.T) {

}

// Test that we can recursively verify the base proof
func TestMimcPlonkNormalCase(t *testing.T) {

}

// Test that we can recursively verify a normal proof
func TestMimcPlonkNormal2(t *testing.T) {

}

func getInnerBasePlonkCircuit2(t *testing.T, field *big.Int, outerPubWitness witness.Witness, outerProof native_plonk.Proof, outerCcs constraint.ConstraintSystem) (constraint.ConstraintSystem, native_plonk.VerifyingKey, witness.Witness, native_plonk.Proof, error) {

	assert := test.NewAssert(t)
	//make the compiler happy
	circuit := &MimcPlonkCircuit[scalarField, g1Affine, g2Affine, gTEl]{
		PreviousWitness: plonk.PlaceholderWitness[scalarField](outerCcs),
		PreviousProof:   plonk.PlaceholderProof[scalarField, g1Affine, g2Affine](outerCcs),
		PreviousVk:      plonk.PlaceholderVerifyingKey[scalarField, g1Affine, g2Affine](outerCcs),
	}

	start := time.Now()
	innerCcs, err := frontend.Compile(field, scs.NewBuilder, circuit)
	assert.NoError(err)
	elapsed := time.Since(start)
	fmt.Printf("Compilation over emulated field took %s\n", elapsed)

	srs, srsLagrange, err := unsafekzg.NewSRS(innerCcs, unsafekzg.WithFSCache())
	assert.NoError(err)

	start = time.Now()
	innerPK, innerVK, err := native_plonk.Setup(innerCcs, srs, srsLagrange)
	assert.NoError(err)
	elapsed = time.Since(start)
	fmt.Printf("Setup over emulated field took %s\n", elapsed)

	circuitVk, err := plonk.ValueOfVerifyingKey[scalarField, g1Affine, g2Affine](innerVK)
	assert.NoError(err)
	circuitPubWitness, err := plonk.ValueOfWitness[scalarField](outerPubWitness)
	//fmt.Printf("nbInnerPubWitness:%v, witness:%v\n", len(circuitPubWitness.Public), circuitPubWitness.Public)

	assert.NoError(err)
	circuitProof, err := plonk.ValueOfProof[scalarField, g1Affine, g2Affine](outerProof)
	assert.NoError(err)

	outerAssignment := &MimcPlonkCircuit[scalarField, g1Affine, g2Affine, gTEl]{
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
	proverOptions := plonk.GetNativeProverOptions(outerCurve.ScalarField(), innerCurve.ScalarField())
	innerProof, err := native_plonk.Prove(innerCcs, innerPK, innerWitness, proverOptions)
	assert.NoError(err)

	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)

	//Verify our new proof
	verifierOptions := plonk.GetNativeVerifierOptions(outerCurve.ScalarField(), innerCurve.ScalarField())
	err = native_plonk.Verify(innerProof, innerVK, innerPubWitness, verifierOptions)
	assert.NoError(err)

	return innerCcs, innerVK, innerPubWitness, innerProof, nil
}

func getInnerBasePlonkCircuit(field *big.Int) (constraint.ConstraintSystem, native_plonk.VerifyingKey, witness.Witness, native_plonk.Proof, error) {
	//make the compiler happy
	circuit := MimcCircuitBase{}

	innerCcs, err := frontend.Compile(field, scs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	srs, srsLagrange, err := unsafekzg.NewSRS(innerCcs, unsafekzg.WithFSCache())

	innerPK, innerVK, err := native_plonk.Setup(innerCcs, srs, srsLagrange)
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
	po := plonk.GetNativeProverOptions(outerCurve.ScalarField(), innerCurve.ScalarField())
	innerProof, err := native_plonk.Prove(innerCcs, innerPK, innerWitness, po)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	vo := plonk.GetNativeVerifierOptions(outerCurve.ScalarField(), innerCurve.ScalarField())
	err = native_plonk.Verify(innerProof, innerVK, innerPubWitness, vo)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return innerCcs, innerVK, innerPubWitness, innerProof, nil
}

func TestRecursivePlonkHashCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	innerCcs, innerVK, innerPubWitness, innerProof, err := getInnerBasePlonkCircuit(innerCurve.ScalarField())
	assert.NoError(err)
	// initialize the witness elements
	circuitVk, err := plonk.ValueOfVerifyingKey[scalarField, g1Affine, g2Affine](innerVK)
	assert.NoError(err)
	circuitPubWitness, err := plonk.ValueOfWitness[scalarField](innerPubWitness)
	fmt.Printf("nbInnerPubWitness:%v, witness:%v\n", len(circuitPubWitness.Public), circuitPubWitness.Public)

	assert.NoError(err)
	circuitProof, err := plonk.ValueOfProof[scalarField, g1Affine, g2Affine](innerProof)
	assert.NoError(err)

	outerAssignment := &MimcPlonkCircuit[scalarField, g1Affine, g2Affine, gTEl]{
		PreviousWitness: circuitPubWitness,
		PreviousProof:   circuitProof,
		PreviousVk:      circuitVk,
		X:               2,
		Y:               3,
		Z:               6,
	}

	outerCircuit := &MimcPlonkCircuit[scalarField, g1Affine, g2Affine, gTEl]{
		PreviousWitness: plonk.PlaceholderWitness[scalarField](innerCcs),
		PreviousProof:   plonk.PlaceholderProof[scalarField, g1Affine, g2Affine](innerCcs),
		PreviousVk:      plonk.PlaceholderVerifyingKey[scalarField, g1Affine, g2Affine](innerCcs),
	}

	err = test.IsSolved(outerCircuit, outerAssignment, outerCurve.ScalarField())
	assert.NoError(err)

	//// compile the outer circuit
	outerCcs, err := frontend.Compile(outerCurve.ScalarField(), scs.NewBuilder, outerCircuit)
	//assert.NoError(err)
	//// create prover witness from the assignment
	outerWitness, err := frontend.NewWitness(outerAssignment, outerCurve.ScalarField())
	//assert.NoError(err)

	//// create public witness from the assignment
	outerPublicWitness, err := outerWitness.Public()
	assert.NoError(err)

	srs, srsLagrange, err := unsafekzg.NewSRS(outerCcs, unsafekzg.WithFSCache())
	assert.NoError(err)

	//// create Groth16 setup. NB! UNSAFE
	outerPk, outerVk, err := native_plonk.Setup(outerCcs, srs, srsLagrange) // UNSAFE! Use MPC
	assert.NoError(err)
	//
	//// construct the groth16 proof of verifying Groth16 proof in-circuit
	proverOptions := plonk.GetNativeProverOptions(outerCurve.ScalarField(), innerCurve.ScalarField())
	outerProof, err := native_plonk.Prove(outerCcs, outerPk, outerWitness, proverOptions)
	assert.NoError(err)
	//
	//// verify the Groth16 proof
	verifierOptions := plonk.GetNativeVerifierOptions(outerCurve.ScalarField(), innerCurve.ScalarField())
	err = native_plonk.Verify(outerProof, outerVk, outerPublicWitness, verifierOptions)
	assert.NoError(err)

	//do next round of proving a new normal proof from previous normal proof
	//innerNormalCcs, innerNormalVK, innerNormalPubWitness, innerNormalProof, err :=  getInnerNormalCircuit(t, innerCurve.ScalarField(), outerCcs, outerPk, outerPublicWitness, outerProof, outerVk)
	//_, _, err = getInnerNormalCircuit(t, innerCurve.ScalarField(), innerNormalCcs, innerNormalPk, newPubInnerWitness, outerProof, innerNormalVK)
	//assert.NoError(err)

	//getInnerBasePlonkCircuit2(t, innerCurve.ScalarField(), outerPublicWitness, outerProof, outerCcs)

}

func getInnerNormalPlonkCircuit(t *testing.T, field *big.Int, innerCcs constraint.ConstraintSystem, prevPk native_plonk.ProvingKey, prevWitness witness.Witness, prevProof native_plonk.Proof, prevVk native_plonk.VerifyingKey) (witness.Witness, native_plonk.Proof, error) {
	assert := test.NewAssert(t)

	circuitPubWitness, err := plonk.ValueOfWitness[scalarField](prevWitness)
	assert.NoError(err)
	fmt.Printf("nbInnerPubWitness:%v, witness:%v\n", len(circuitPubWitness.Public), circuitPubWitness.Public)
	circuitVk, err := plonk.ValueOfVerifyingKey[scalarField, g1Affine, g2Affine](prevVk)
	assert.NoError(err)

	circuitProof, err := plonk.ValueOfProof[scalarField, g1Affine, g2Affine](prevProof)
	assert.NoError(err)

	innerAssignment := &MimcPlonkCircuit[scalarField, g1Affine, g2Affine, gTEl]{
		PreviousWitness: circuitPubWitness,
		PreviousProof:   circuitProof,
		PreviousVk:      circuitVk,
		X:               2,
		Y:               3,
		Z:               6,
	}

	proverOptions := plonk.GetNativeProverOptions(outerCurve.ScalarField(), innerCurve.ScalarField())
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	if err != nil {
		return nil, nil, err
	}
	innerProof, err := native_plonk.Prove(innerCcs, prevPk, innerWitness, proverOptions)
	if err != nil {
		return nil, nil, err
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		return nil, nil, err
	}
	verifierOptions := plonk.GetNativeVerifierOptions(outerCurve.ScalarField(), innerCurve.ScalarField())
	err = native_plonk.Verify(innerProof, prevVk, innerPubWitness, verifierOptions)
	if err != nil {
		return nil, nil, err
	}

	return innerPubWitness, innerProof, nil
}

func getPlonkParams(innerField *big.Int, innerCcs constraint.ConstraintSystem) (constraint.ConstraintSystem, native_plonk.ProvingKey, native_plonk.VerifyingKey, error) {

	circuit := &MimcPlonkCircuit[scalarField, g1Affine, g2Affine, gTEl]{
		PreviousWitness: plonk.PlaceholderWitness[scalarField](innerCcs),
		PreviousProof:   plonk.PlaceholderProof[scalarField, g1Affine, g2Affine](innerCcs),
		PreviousVk:      plonk.PlaceholderVerifyingKey[scalarField, g1Affine, g2Affine](innerCcs),
	}

	innerNormalCcs, err := frontend.Compile(innerField, scs.NewBuilder, circuit)
	if err != nil {
		return nil, nil, nil, err
	}

	srs, srsLagrange, err := unsafekzg.NewSRS(innerCcs, unsafekzg.WithFSCache())

	innerPK, innerVK, err := native_plonk.Setup(innerCcs, srs, srsLagrange)
	if err != nil {
		return nil, nil, nil, err
	}

	return innerNormalCcs, innerPK, innerVK, nil
}
