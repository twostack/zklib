package recurse

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
	"math/big"
	"testing"
	plonk2 "zklib/twostack/plonk"
)

func TestInnerProofCircuitPlonk(t *testing.T) {

	//Deconstructed P2PKH Transaction
	prefixBytes, _ := hex.DecodeString("0200000001")
	prevTxnIdBytes, _ := hex.DecodeString("ae4b7f1769154bb04e9c666a4dbb31eb2ec0c4e01d965cbb1ca4574e7ed40a19")
	postFixBytes, _ := hex.DecodeString("000000004847304402200e993f6bc2319615b662ac7f5882bc78dc35101d1b110a0edf2fd79dea2206c2022017e352e87390227a39b7eae6510cdff9e1cedc8a517e811b90ac6b6fdc8d7d0441feffffff0200ca9a3b000000001976a914783b608b9278a187641d047c14dbf63e1be5bc8888ac00196bee000000001976a9142bfccc428186e69fc94fde6d7396f19482dd5a7988ac65000000")

	fullTxBytes, _ := hex.DecodeString("0200000001ae4b7f1769154bb04e9c666a4dbb31eb2ec0c4e01d965cbb1ca4574e7ed40a19000000004847304402200e993f6bc2319615b662ac7f5882bc78dc35101d1b110a0edf2fd79dea2206c2022017e352e87390227a39b7eae6510cdff9e1cedc8a517e811b90ac6b6fdc8d7d0441feffffff0200ca9a3b000000001976a914783b608b9278a187641d047c14dbf63e1be5bc8888ac00196bee000000001976a9142bfccc428186e69fc94fde6d7396f19482dd5a7988ac65000000")

	firstHash := sha256.Sum256(fullTxBytes)
	currTxId := sha256.Sum256(firstHash[:])
	fmt.Println(currTxId)

	fmt.Println(hex.EncodeToString(currTxId[:]))

	//full witness
	witness := plonk2.Sha256InnerCircuit{}
	copy(witness.PrevTxId[:], uints.NewU8Array(prevTxnIdBytes))
	copy(witness.CurrTxPost[:], uints.NewU8Array(postFixBytes))
	copy(witness.CurrTxPrefix[:], uints.NewU8Array(prefixBytes))
	copy(witness.CurrTxId[:], uints.NewU8Array(currTxId[:]))

	// inner circuit pre-image values only
	testCircuit := plonk2.Sha256InnerCircuit{}
	copy(testCircuit.PrevTxId[:], uints.NewU8Array(prevTxnIdBytes))
	copy(testCircuit.CurrTxPost[:], uints.NewU8Array(postFixBytes))
	copy(testCircuit.CurrTxPrefix[:], uints.NewU8Array(prefixBytes))

	//test circuit execution
	err := test.IsSolved(&testCircuit, &witness, ecc.BLS12_377.ScalarField())

	if err != nil {
		t.Fatal(err)
	}

	//test the prover
	assert := test.NewAssert(t)

	proverCircuit := plonk2.Sha256InnerCircuit{}
	copy(proverCircuit.CurrTxId[:], uints.NewU8Array(currTxId[:]))
	copy(proverCircuit.PrevTxId[:], uints.NewU8Array(prevTxnIdBytes))
	copy(proverCircuit.CurrTxPost[:], uints.NewU8Array(postFixBytes))
	copy(proverCircuit.CurrTxPrefix[:], uints.NewU8Array(prefixBytes))

	assert.ProverSucceeded(&plonk2.Sha256InnerCircuit{}, &proverCircuit, test.WithCurves(ecc.BLS12_377))

}

// deserialise existing inner proof, and check that we can verify that proof
// inside our outer-circuit
func TestOuterProofCircuitPlonk(t *testing.T) {

}

func TestInnerProofComputeAndVerifyPlonk(t *testing.T) {
	//innerCcs, innerVK, innerWitness, innerProof :=

	//innerCcs, innerVK, innerWitness, innerProof :=
	//computeInnerProofPlonk(ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField())
	Example_emulated()
}

func TestOuterProofAndVerifyPlonkSuccinct(t *testing.T) {

	//innerCcs, innerVK, innerWitness, innerProof := computeInnerProof(ecc.BLS12_377.ScalarField())
	//computeInnerProofPlonk(ecc.BLS12_377.ScalarField())

	//innerCcs, innerVK, innerWitness, innerProof :=
	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := computeInnerProofPlonk(assert, ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField())

	circuitVk, err := plonk.ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerVK)
	if err != nil {
		panic(err)
	}
	circuitWitness, err := plonk.ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	if err != nil {
		panic(err)
	}
	circuitProof, err := plonk.ValueOfProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	if err != nil {
		panic(err)
	}

	outerCircuit := &plonk2.Sha256OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: plonk.PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
		Proof:        plonk.PlaceholderProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerCcs),
		VerifyingKey: circuitVk,
	}
	outerAssignment := &plonk2.Sha256OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
	}

	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField())
	assert.NoError(err)

}

func TestOuterProofAndVerifyPlonk(t *testing.T) {

	//innerCcs, innerVK, innerWitness, innerProof := computeInnerProof(ecc.BLS12_377.ScalarField())
	//computeInnerProofPlonk(ecc.BLS12_377.ScalarField())

	//innerCcs, innerVK, innerWitness, innerProof :=
	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := computeInnerProofPlonk(assert, ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField())

	circuitVk, err := plonk.ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerVK)
	if err != nil {
		panic(err)
	}
	circuitWitness, err := plonk.ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	if err != nil {
		panic(err)
	}
	circuitProof, err := plonk.ValueOfProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	if err != nil {
		panic(err)
	}

	prevTxnIdBytes, _ := hex.DecodeString("193a78f8a6883ae82d7e9f146934af4d6edc2f0f5a16d0b931bdfaa9a0d22eac")
	outerCircuit := &plonk2.Sha256OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: plonk.PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
		Proof:        plonk.PlaceholderProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerCcs),
		VerifyingKey: circuitVk,
	}
	copy(outerCircuit.PrevTxId[:], uints.NewU8Array(prevTxnIdBytes))

	outerAssignment := &plonk2.Sha256OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
	}
	copy(outerAssignment.PrevTxId[:], uints.NewU8Array(prevTxnIdBytes))

	// compile the outer circuit
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, outerCircuit)
	if err != nil {
		panic("compile failed: " + err.Error())
	}

	// NB! UNSAFE! Use MPC.
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		panic(err)
	}

	// create PLONK setup. NB! UNSAFE
	pk, vk, err := native_plonk.Setup(ccs, srs, srsLagrange) // UNSAFE! Use MPC
	if err != nil {
		panic("setup failed: " + err.Error())
	}

	// create prover witness from the assignment
	secretWitness, err := frontend.NewWitness(outerAssignment, ecc.BW6_761.ScalarField())
	if err != nil {
		panic("secret witness failed: " + err.Error())
	}

	// create public witness from the assignment
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic("public witness failed: " + err.Error())
	}

	// construct the PLONK proof of verifying PLONK proof in-circuit
	outerProof, err := native_plonk.Prove(ccs, pk, secretWitness)
	if err != nil {
		panic("proving failed: " + err.Error())
	}

	// verify the PLONK proof
	err = native_plonk.Verify(outerProof, vk, publicWitness)
	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}
}

// computeInnerProof computes the proof for the inner circuit we want to verify
// recursively. In this example the Groth16 keys are generated on the fly, but
// in practice should be generated once and using MPC.

func computeInnerProofPlonk(assert *test.Assert, field, outer *big.Int) (constraint.ConstraintSystem, native_plonk.VerifyingKey, witness.Witness, native_plonk.Proof) {
	//func computeInnerProofPlonk(field *big.Int) (constraint.ConstraintSystem, plonk.PreviousVk, witness.Witness, plonk.PreviousProof) {
	//innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &Sha256InnerCircuit{})
	innerCcs, err := frontend.Compile(field, scs.NewBuilder, &plonk2.Sha256InnerCircuit{})

	if err != nil {
		panic(err)
	}

	srs, srsLagrange, err := unsafekzg.NewSRS(innerCcs)

	if err != nil {
		panic(err)
	}

	innerPK, innerVK, err := native_plonk.Setup(innerCcs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}

	prefixBytes, _ := hex.DecodeString("0200000001")
	prevTxnIdBytes, _ := hex.DecodeString("ae4b7f1769154bb04e9c666a4dbb31eb2ec0c4e01d965cbb1ca4574e7ed40a19")
	postFixBytes, _ := hex.DecodeString("000000004847304402200e993f6bc2319615b662ac7f5882bc78dc35101d1b110a0edf2fd79dea2206c2022017e352e87390227a39b7eae6510cdff9e1cedc8a517e811b90ac6b6fdc8d7d0441feffffff0200ca9a3b000000001976a914783b608b9278a187641d047c14dbf63e1be5bc8888ac00196bee000000001976a9142bfccc428186e69fc94fde6d7396f19482dd5a7988ac65000000")

	fullTxBytes, _ := hex.DecodeString("0200000001ae4b7f1769154bb04e9c666a4dbb31eb2ec0c4e01d965cbb1ca4574e7ed40a19000000004847304402200e993f6bc2319615b662ac7f5882bc78dc35101d1b110a0edf2fd79dea2206c2022017e352e87390227a39b7eae6510cdff9e1cedc8a517e811b90ac6b6fdc8d7d0441feffffff0200ca9a3b000000001976a914783b608b9278a187641d047c14dbf63e1be5bc8888ac00196bee000000001976a9142bfccc428186e69fc94fde6d7396f19482dd5a7988ac65000000")

	firstHash := sha256.Sum256(fullTxBytes)
	currTxId := sha256.Sum256(firstHash[:])

	fmt.Println(hex.EncodeToString(currTxId[:]))
	// inner proof
	innerAssignment := &plonk2.Sha256InnerCircuit{}

	copy(innerAssignment.CurrTxPrefix[:], uints.NewU8Array(prefixBytes))
	copy(innerAssignment.CurrTxPost[:], uints.NewU8Array(postFixBytes))
	copy(innerAssignment.PrevTxId[:], uints.NewU8Array(prevTxnIdBytes))
	copy(innerAssignment.CurrTxId[:], uints.NewU8Array(currTxId[:]))

	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	assert.NoError(err)
	innerProof, err := native_plonk.Prove(innerCcs, innerPK, innerWitness, plonk.GetNativeProverOptions(outer, field))
	assert.NoError(err)
	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)
	err = native_plonk.Verify(innerProof, innerVK, innerPubWitness, plonk.GetNativeVerifierOptions(outer, field))
	assert.NoError(err)
	return innerCcs, innerVK, innerPubWitness, innerProof

}

// /emulation takes donkey years. Probably impractical
func Example_emulated() {
	/* can't set fr.Element from type expr.Term
	// compute the proof which we want to verify recursively
	innerCcs, innerVK, innerWitness, innerProof := computeInnerProofPlonk(ecc.BW6_761.ScalarField(), ecc.BN254.ScalarField())

	// initialize the witness elements
	circuitVk, err := plonk.ValueOfVerifyingKey[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerVK)
	if err != nil {
		panic(err)
	}
	circuitWitness, err := plonk.ValueOfWitness[sw_bw6761.ScalarField](innerWitness)
	if err != nil {
		panic(err)
	}
	circuitProof, err := plonk.ValueOfProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerProof)
	if err != nil {
		panic(err)
	}

	outerCircuit := &Sha256OuterCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		PreviousWitness: plonk.PlaceholderWitness[sw_bw6761.ScalarField](innerCcs),
		PreviousProof:        plonk.PlaceholderProof[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine](innerCcs),
		PreviousVk: circuitVk,
	}
	outerAssignment := &Sha256OuterCircuit[sw_bw6761.ScalarField, sw_bw6761.G1Affine, sw_bw6761.G2Affine, sw_bw6761.GTEl]{
		PreviousWitness: circuitWitness,
		PreviousProof:        circuitProof,
	}
	// compile the outer circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, outerCircuit)
	if err != nil {
		panic("compile failed: " + err.Error())
	}

	// NB! UNSAFE! Use MPC.
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		panic(err)
	}

	// create PLONK setup. NB! UNSAFE
	pk, vk, err := native_plonk.Setup(ccs, srs, srsLagrange) // UNSAFE! Use MPC
	if err != nil {
		panic("setup failed: " + err.Error())
	}

	// create prover witness from the assignment
	secretWitness, err := frontend.NewWitness(outerAssignment, ecc.BN254.ScalarField())
	if err != nil {
		panic("secret witness failed: " + err.Error())
	}

	// create public witness from the assignment
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic("public witness failed: " + err.Error())
	}

	// construct the PLONK proof of verifying PLONK proof in-circuit
	outerProof, err := native_plonk.Prove(ccs, pk, secretWitness)
	if err != nil {
		panic("proving failed: " + err.Error())
	}

	// verify the PLONK proof
	err = native_plonk.Verify(outerProof, vk, publicWitness)
	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}

	*/
}
