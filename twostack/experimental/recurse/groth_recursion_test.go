package recurse

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/consensys/gnark-crypto/ecc"
	native_groth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

var InnerCurve = ecc.BLS12_377
var OuterCurve = ecc.BW6_761

type ScalarField = sw_bls12377.ScalarField
type G1Affine = sw_bls12377.G1Affine
type G2Affine = sw_bls12377.G2Affine
type GTEl = sw_bls12377.GT

//var InnerCurve = ecc.BLS24_315
//var OuterCurve = ecc.BW6_633
//
//type ScalarField = sw_bls24315.ScalarField
//type G1Affine = sw_bls24315.G1Affine
//type G2Affine = sw_bls24315.G2Affine
//type GTEl = sw_bls24315.GT

//type ScalarField = sw_bls12381.ScalarField
//type G1Affine = sw_bls12381.G1Affine
//type G2Affine = sw_bls12381.G2Affine
//type GTEl = sw_bls12381.GTEl

// type ScalarField = sw_bn254.ScalarField
// type G1Affine = sw_bn254.G1Affine
// type G2Affine = sw_bn254.G2Affine
// type GTEl = sw_bn254.GTEl

//type ScalarField = sw_bls24315.ScalarField
//type G1Affine = sw_bls24315.G1Affine
//type G2Affine = sw_bls24315.G2Affine
//type GTEl = sw_bls24315.GT

func TestGrothOuterProof(t *testing.T) {
	//innerField := ecc.BLS12_377.ScalarField()
	//outerField := ecc.BW6_761.ScalarField()

	assert := test.NewAssert(t)
	//assert := test.NewAssert(t)
	//innerCcs, innerVK, innerWitness, innerProof := computeInnerProof(ecc.BLS12_377.ScalarField())

	innerCcs, innerVK, innerPubWitness, innerProof, err := computeGrothInnerProof(t, OuterCurve.ScalarField(), InnerCurve.ScalarField())

	//now verify the outer proof
	assert.NoError(err)
	genesisWitness, err := groth16.ValueOfWitness[ScalarField](*innerPubWitness)
	assert.NoError(err)
	genesisProof, err := groth16.ValueOfProof[G1Affine, G2Affine](*innerProof)
	assert.NoError(err)
	genesisVk, err := groth16.ValueOfVerifyingKey[G1Affine, G2Affine, GTEl](*innerVK)
	assert.NoError(err)

	//spending tx info
	assert.NoError(err)
	outerCircuit := &Sha256CircuitOuter[ScalarField, G1Affine, G2Affine, GTEl]{
		PreviousWitness: groth16.PlaceholderWitness[ScalarField](*innerCcs),
		//PreviousVk:      genesisVk,
		PreviousProof: groth16.PlaceholderProof[G1Affine, G2Affine](*innerCcs),
		PreviousVk:    groth16.PlaceholderVerifyingKey[G1Affine, G2Affine, GTEl](*innerCcs),
	}

	//dummyTxId, err := hex.DecodeString("faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71")
	//copy(outerCircuit.CurrTxId[:], uints.NewU8Array(dummyTxId[:]))

	outerAssignment := Sha256CircuitOuter[ScalarField, G1Affine, G2Affine, GTEl]{
		PreviousWitness: genesisWitness,
		PreviousProof:   genesisProof,
		PreviousVk:      genesisVk,
	}
	//copy(outerAssignment.CurrTxId[:], uints.NewU8Array(dummyTxId[:]))

	err = test.IsSolved(outerCircuit, &outerAssignment, OuterCurve.ScalarField())
	assert.NoError(err)

	//outerCcs, err := frontend.Compile(OuterCurve.ScalarField(), r1cs.NewBuilder, outerCircuitPlonk)
	//assert.NoError(err)
	//
	//outerPk, outerVK, err := native_groth16.Setup(outerCcs)
	//assert.NoError(err)
	//
	//outerWitness, err := frontend.NewWitness(&outerAssignment, OuterCurve.ScalarField())
	//outerProof, err := native_groth16.Prove(outerCcs, outerPk, outerWitness, groth16.GetNativeProverOptions(OuterCurve.ScalarField(), InnerCurve.ScalarField()))
	//
	//
	////verify the normal proof
	//assert.NoError(err)
	//publicWitness, err := outerWitness.Public()
	//assert.NoError(err)
	//err = native_groth16.Verify(outerProof, outerVK, publicWitness, groth16.GetNativeVerifierOptions(InnerCurve.ScalarField(), InnerCurve.ScalarField()))
	//assert.NoError(err)
}

// computeGrothInnerProof computes the proof for the inner circuit we want to verify
// recursively. In this example the Groth16 keys are generated on the fly, but
// in practice should be generated once and using MPC.
func computeGrothInnerProof(t *testing.T, outerField, innerField *big.Int) (*constraint.ConstraintSystem, *native_groth16.VerifyingKey, *witness.Witness, *native_groth16.Proof, error) {

	assert := test.NewAssert(t)
	fullTxBytes, _ := hex.DecodeString("0200000001ae4b7f1769154bb04e9c666a4dbb31eb2ec0c4e01d965cbb1ca4574e7ed40a19000000004847304402200e993f6bc2319615b662ac7f5882bc78dc35101d1b110a0edf2fd79dea2206c2022017e352e87390227a39b7eae6510cdff9e1cedc8a517e811b90ac6b6fdc8d7d0441feffffff0200ca9a3b000000001976a914783b608b9278a187641d047c14dbf63e1be5bc8888ac00196bee000000001976a9142bfccc428186e69fc94fde6d7396f19482dd5a7988ac65000000")
	firstHash := sha256.Sum256(fullTxBytes)
	currTxId := sha256.Sum256(firstHash[:])

	innerCcs, err := frontend.Compile(innerField, r1cs.NewBuilder,
		&Sha256CircuitInner{})
	assert.NoError(err)

	innerPK, innerVK, err := native_groth16.Setup(innerCcs)
	assert.NoError(err)

	// inner proof
	innerAssignment := &Sha256CircuitInner{
		//RawTx:    make([]uints.U8, len(fullTxBytes)),
		//CurrTxId: make([]uints.U8, 32),
		RawTx:    uints.NewU8Array(fullTxBytes[:]),
		CurrTxId: uints.NewU8Array(currTxId[:]),
	}
	//copy(innerAssignment.RawTx[:], uints.NewU8Array(fullTxBytes[:]))
	//copy(innerAssignment.CurrTxId[:], uints.NewU8Array(currTxId[:]))
	//for ndx := 0; ndx < len(fullTxBytes); ndx++ {
	//	innerAssignment.RawTx[ndx] = fullTxBytes[ndx]
	//}
	//for ndx := 0; ndx < len(currTxId); ndx++ {
	//	innerAssignment.CurrTxId[ndx] = currTxId[ndx]
	//}

	innerWitness, err := frontend.NewWitness(innerAssignment, innerField)
	assert.NoError(err)

	innerProof, err := native_groth16.Prove(innerCcs, innerPK, innerWitness, groth16.GetNativeProverOptions(outerField, innerField))
	assert.NoError(err)

	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)

	err = native_groth16.Verify(innerProof, innerVK, innerPubWitness, groth16.GetNativeVerifierOptions(outerField, innerField))
	assert.NoError(err)

	return &innerCcs, &innerVK, &innerPubWitness, &innerProof, nil
}
