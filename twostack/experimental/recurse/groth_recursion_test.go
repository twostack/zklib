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

type ScalarField = sw_bls12377.ScalarField
type G1Affine = sw_bls12377.G1Affine
type G2Affine = sw_bls12377.G2Affine
type GTEl = sw_bls12377.GT

func TestGrothOuterProof(t *testing.T) {
	innerField := ecc.BLS12_377.ScalarField()
	outerField := ecc.BW6_761.ScalarField()

	assert := test.NewAssert(t)
	//assert := test.NewAssert(t)
	//innerCcs, innerVK, innerWitness, innerProof := computeInnerProof(ecc.BLS12_377.ScalarField())
	_, innerVK, innerWitness, innerProof := computeGrothInnerProof(t, innerField)

	//now verify the outer proof

	genesisWitness, err := groth16.ValueOfWitness[ScalarField](innerWitness)
	assert.NoError(err)
	genesisProof, err := groth16.ValueOfProof[G1Affine, G2Affine](innerProof)
	assert.NoError(err)
	genesisVk, err := groth16.ValueOfVerifyingKey[G1Affine, G2Affine, GTEl](innerVK)
	assert.NoError(err)

	//spending tx info
	assert.NoError(err)
	outerCircuit := &Sha256CircuitOuter[ScalarField, G1Affine, G2Affine, GTEl]{
		//PreviousWitness: groth16.PlaceholderWitness[ScalarField](innerCcs),
		////PreviousVk:      genesisVk,
		//PreviousVk:    groth16.PlaceholderVerifyingKey[G1Affine, G2Affine, GTEl](innerCcs),
		//PreviousProof: groth16.PlaceholderProof[G1Affine, G2Affine](innerCcs),

	}

	outerCcs, err := frontend.Compile(outerField, r1cs.NewBuilder, outerCircuit)
	assert.NoError(err)

	outerPk, outerVK, err := native_groth16.Setup(outerCcs)
	assert.NoError(err)

	outerAssignment := Sha256CircuitOuter[ScalarField, G1Affine, G2Affine, GTEl]{
		PreviousWitness: genesisWitness,
		PreviousProof:   genesisProof,
		PreviousVk:      genesisVk,
	}

	outerWitness, err := frontend.NewWitness(&outerAssignment, outerField)
	outerProof, err := native_groth16.Prove(outerCcs, outerPk, outerWitness, groth16.GetNativeProverOptions(outerField, innerField))

	//verify the normal proof
	assert.NoError(err)
	publicWitness, err := outerWitness.Public()
	assert.NoError(err)
	err = native_groth16.Verify(outerProof, outerVK, publicWitness, groth16.GetNativeVerifierOptions(outerField, innerField))
	assert.NoError(err)
}

// computeGrothInnerProof computes the proof for the inner circuit we want to verify
// recursively. In this example the Groth16 keys are generated on the fly, but
// in practice should be generated once and using MPC.
func computeGrothInnerProof(t *testing.T, field *big.Int) (constraint.ConstraintSystem, native_groth16.VerifyingKey, witness.Witness, native_groth16.Proof) {

	assert := test.NewAssert(t)
	fullTxBytes, _ := hex.DecodeString("0200000001ae4b7f1769154bb04e9c666a4dbb31eb2ec0c4e01d965cbb1ca4574e7ed40a19000000004847304402200e993f6bc2319615b662ac7f5882bc78dc35101d1b110a0edf2fd79dea2206c2022017e352e87390227a39b7eae6510cdff9e1cedc8a517e811b90ac6b6fdc8d7d0441feffffff0200ca9a3b000000001976a914783b608b9278a187641d047c14dbf63e1be5bc8888ac00196bee000000001976a9142bfccc428186e69fc94fde6d7396f19482dd5a7988ac65000000")
	firstHash := sha256.Sum256(fullTxBytes)
	currTxId := sha256.Sum256(firstHash[:])

	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder,
		&Sha256CircuitInner[ScalarField, G1Affine, G2Affine, GTEl]{
			RawTx: make([]uints.U8, len(fullTxBytes)),
		})
	assert.NoError(err)

	innerPK, innerVK, err := native_groth16.Setup(innerCcs)
	assert.NoError(err)

	// inner proof
	innerAssignment := &Sha256CircuitInner[ScalarField, G1Affine, G2Affine, GTEl]{
		RawTx: uints.NewU8Array(fullTxBytes),
	}
	copy(innerAssignment.CurrTxId[:], uints.NewU8Array(currTxId[:]))

	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	assert.NoError(err)

	innerProof, err := native_groth16.Prove(innerCcs, innerPK, innerWitness)
	assert.NoError(err)

	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)

	err = native_groth16.Verify(innerProof, innerVK, innerPubWitness)
	assert.NoError(err)

	return innerCcs, innerVK, innerPubWitness, innerProof
}
