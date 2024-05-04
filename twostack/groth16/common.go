package txivc

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	native_groth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/groth16"
	"math/big"
)

type BaseProofInfo struct {
	RawTx string `json:"raw_tx" binding:"required"`
}
type NormalProofInfo struct {
	RawTx        string `json:"raw_tx" binding:"required"`
	InputIndex   int    `json:"input_index"`
	IsParentBase bool   `json:"is_parent_base"`
	Proof        string `json:"proof" binding:"required"`
}

var InnerCurve = ecc.BLS12_377
var OuterCurve = ecc.BW6_761

type ScalarField = sw_bls12377.ScalarField
type G1Affine = sw_bls12377.G1Affine
type G2Affine = sw_bls12377.G2Affine
type GTEl = sw_bls12377.GT

//var InnerCurve = ecc.BLS24_315
//var OuterCurve = ecc.BW6_633

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

func SetupBaseCase(txSize int, innerField *big.Int) (constraint.ConstraintSystem, native_groth16.ProvingKey, native_groth16.VerifyingKey, error) {

	baseCcs, err := frontend.Compile(innerField, r1cs.NewBuilder,
		&Sha256CircuitBaseCase[ScalarField, G1Affine, G2Affine, GTEl]{
			RawTx: make([]uints.U8, txSize),
		})

	if err != nil {
		return nil, nil, nil, err
	}

	innerPK, innerVK, err := native_groth16.Setup(baseCcs)
	if err != nil {
		return nil, nil, nil, err
	}
	return baseCcs, innerPK, innerVK, nil
}

func SetupNormalCase(outerField *big.Int, parentCcs *constraint.ConstraintSystem, parentVk *native_groth16.VerifyingKey) (constraint.ConstraintSystem, native_groth16.ProvingKey, native_groth16.VerifyingKey, error) {

	previousVk, err := groth16.ValueOfVerifyingKey[G1Affine, G2Affine, GTEl](*parentVk)
	if err != nil {
		fmt.Printf("Error compile normal circuit : %s", err)
		return nil, nil, nil, err
	}

	innerCcs, err := frontend.Compile(outerField, r1cs.NewBuilder,
		&Sha256Circuit[ScalarField, G1Affine, G2Affine, GTEl]{
			PreviousProof: groth16.PlaceholderProof[G1Affine, G2Affine](*parentCcs),
			PreviousVk:    previousVk,
			//PreviousVk:      groth16.PlaceholderVerifyingKey[G1Affine, G2Affine, GTEl](*parentCcs),
			PreviousWitness: groth16.PlaceholderWitness[ScalarField](*parentCcs),
		})

	if err != nil {
		fmt.Printf("Error compile normal circuit : %s", err)
		return nil, nil, nil, err
	}

	innerPK, innerVK, err := native_groth16.Setup(innerCcs)
	if err != nil {
		fmt.Printf("Error during setup of normal circuit : %s", err)
		return nil, nil, nil, err
	}
	return innerCcs, innerPK, innerVK, nil
}

func CreateBaseCaseLightWitness(
	currTxId []byte,
	innerField *big.Int,
) (*witness.Witness, error) {

	innerAssignment := Sha256CircuitBaseCase[ScalarField, G1Affine, G2Affine, GTEl]{}

	copy(innerAssignment.CurrTxId[:], uints.NewU8Array(currTxId[:]))

	innerWitness, err := frontend.NewWitness(&innerAssignment, innerField)
	if err != nil {
		return nil, err
	}
	return &innerWitness, nil
}

func CreateBaseCaseFullWitness(
	rawTxBytes []byte,
	currTxId [32]byte,
) (witness.Witness, error) {

	innerAssignment := Sha256CircuitBaseCase[ScalarField, G1Affine, G2Affine, GTEl]{
		RawTx: make([]uints.U8, len(rawTxBytes)),
	}

	//assign the current Txn data
	//for ndx, entry := range rawTxBytes {
	//	innerAssignment.RawTx[ndx] = uints.NewU8(entry)
	//}

	copy(innerAssignment.RawTx[:], uints.NewU8Array(rawTxBytes))
	copy(innerAssignment.CurrTxId[:], uints.NewU8Array(currTxId[:]))

	innerWitness, err := frontend.NewWitness(&innerAssignment, InnerCurve.ScalarField())
	if err != nil {
		return nil, err
	}
	return innerWitness, nil
}

/*
*
Full witness is used for generating a new proof
*/
func CreateNormalFullWitness(
	innerWitness witness.Witness,
	innerProof native_groth16.Proof,
	innerVk native_groth16.VerifyingKey,
	prefixBytes []byte, prevTxnIdBytes []byte, postFixBytes []byte, currTxId []byte, field *big.Int) (witness.Witness, error) {

	circuitVk, err := groth16.ValueOfVerifyingKey[G1Affine, G2Affine, GTEl](innerVk)
	circuitWitness, err := groth16.ValueOfWitness[ScalarField](innerWitness)
	circuitProof, err := groth16.ValueOfProof[G1Affine, G2Affine](innerProof)

	outerAssignment := CreateOuterAssignment(circuitWitness, circuitProof, circuitVk, prefixBytes, prevTxnIdBytes, postFixBytes, currTxId)
	fullWitness, err := frontend.NewWitness(&outerAssignment, field)

	if err != nil {
		return nil, err
	}

	return fullWitness, nil
}

/*
*
Light witness is used for verification of an existing proof. I.e. only public params are filled.
*/
func CreateNormalLightWitness(currTxId []byte, field *big.Int) (*witness.Witness, error) {

	outerAssignment := Sha256Circuit[ScalarField, G1Affine, G2Affine, GTEl]{}

	copy(outerAssignment.CurrTxId[:], uints.NewU8Array(currTxId[:]))

	lightWitness, err := frontend.NewWitness(&outerAssignment, field)

	if err != nil {
		return nil, err
	}

	return &lightWitness, nil

}

func CreateOuterAssignment(
	circuitWitness groth16.Witness[ScalarField],
	circuitProof groth16.Proof[G1Affine, G2Affine],
	verifyingKey groth16.VerifyingKey[G1Affine, G2Affine, GTEl],
	prefixBytes []byte, prevTxnIdBytes []byte, postFixBytes []byte, currTxId []byte) Sha256Circuit[ScalarField, G1Affine, G2Affine, GTEl] {

	outerAssignment := Sha256Circuit[ScalarField, G1Affine, G2Affine, GTEl]{
		PreviousWitness: circuitWitness,
		PreviousProof:   circuitProof,
		PreviousVk:      verifyingKey,
	}

	copy(outerAssignment.CurrTxPrefix[:], uints.NewU8Array(prefixBytes))
	copy(outerAssignment.CurrTxPost[:], uints.NewU8Array(postFixBytes))
	copy(outerAssignment.PrevTxId[:], uints.NewU8Array(prevTxnIdBytes))
	copy(outerAssignment.CurrTxId[:], uints.NewU8Array(currTxId[:]))

	//tokenId := [32]byte{}
	//copy(tokenId[:], prevTxnIdBytes)
	//copy(outerAssignment.TokenId[:], uints.NewU8Array(tokenId[:]))

	return outerAssignment
}

func VerifyProof(genesisWitness witness.Witness, genesisProof native_groth16.Proof, verifyingKey native_groth16.VerifyingKey) bool {
	publicWitness, err := genesisWitness.Public()
	verifierOptions := groth16.GetNativeVerifierOptions(OuterCurve.ScalarField(), InnerCurve.ScalarField())
	err = native_groth16.Verify(genesisProof, verifyingKey, publicWitness, verifierOptions)
	if err != nil {
		fmt.Printf("Fail on base case verification! %s\n", err)
		return false
	}
	return true
}

func ComputeProof(ccs *constraint.ConstraintSystem, provingKey *native_groth16.ProvingKey, outerWitness witness.Witness) (native_groth16.Proof, error) {

	proverOptions := groth16.GetNativeProverOptions(OuterCurve.ScalarField(), InnerCurve.ScalarField())
	return native_groth16.Prove(*ccs, *provingKey, outerWitness, proverOptions)
}
