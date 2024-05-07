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
		&Sha256CircuitBaseCase{
			RawTx:    make([]frontend.Variable, txSize),
			CurrTxId: make([]frontend.Variable, 32), //32 bytes for the txId
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

func SetupNormalCase(prefixSize int, postfixSize int, outerField *big.Int, parentCcs *constraint.ConstraintSystem) (constraint.ConstraintSystem, native_groth16.ProvingKey, native_groth16.VerifyingKey, error) {

	outerCcs, err := frontend.Compile(outerField, r1cs.NewBuilder,
		&Sha256Circuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
			PreviousProof:   groth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](*parentCcs),
			PreviousVk:      groth16.PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](*parentCcs),
			PreviousWitness: groth16.PlaceholderWitness[sw_bls12377.ScalarField](*parentCcs),

			CurrTxPrefix: make([]frontend.Variable, prefixSize),
			CurrTxPost:   make([]frontend.Variable, postfixSize),
			PrevTxId:     make([]frontend.Variable, 32),
			CurrTxId:     make([]frontend.Variable, 32),
		})

	if err != nil {
		fmt.Printf("Error compile normal circuit : %s", err)
		return nil, nil, nil, err
	}

	outerPk, outerVk, err := native_groth16.Setup(outerCcs)
	if err != nil {
		fmt.Printf("Error during setup of normal circuit : %s", err)
		return nil, nil, nil, err
	}
	return outerCcs, outerPk, outerVk, nil
}

func CreateBaseCaseLightWitness(
	currTxId []byte,
	innerField *big.Int,
) (*witness.Witness, error) {

	innerAssignment := Sha256CircuitBaseCase{
		CurrTxId: make([]frontend.Variable, 32),
	}

	//copy(innerAssignment.CurrTxId[:], uints.NewU8Array(currTxId[:]))
	for ndx, entry := range currTxId {
		innerAssignment.CurrTxId[ndx] = entry
	}

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

	innerAssignment := Sha256CircuitBaseCase{
		RawTx:    make([]frontend.Variable, len(rawTxBytes)),
		CurrTxId: make([]frontend.Variable, len(currTxId)),
	}

	//assign the current Txn data
	for ndx := range rawTxBytes {
		innerAssignment.RawTx[ndx] = rawTxBytes[ndx]
	}
	for ndx := range currTxId {
		innerAssignment.CurrTxId[ndx] = currTxId[ndx]
	}

	innerWitness, err := frontend.NewWitness(&innerAssignment, ecc.BLS12_377.ScalarField())
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

	circuitVk, err := groth16.ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVk)
	circuitWitness, err := groth16.ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	circuitProof, err := groth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)

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
func CreateNormalLightWitness(txId []byte, outerField *big.Int) (*witness.Witness, error) {

	outerAssignment := Sha256Circuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		CurrTxId: make([]frontend.Variable, 32),
	}

	lightWitness, err := frontend.NewWitness(&outerAssignment, outerField)

	if err != nil {
		return nil, err
	}

	return &lightWitness, nil

}

func CreateOuterAssignment(
	circuitWitness groth16.Witness[sw_bls12377.ScalarField],
	circuitProof groth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine],
	verifyingKey groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT],
	prefixBytes []byte, prevTxnIdBytes []byte, postFixBytes []byte, currTxId []byte) Sha256Circuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT] {

	outerAssignment := Sha256Circuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		PreviousWitness: circuitWitness,
		PreviousProof:   circuitProof,
		PreviousVk:      verifyingKey,

		CurrTxPrefix: make([]frontend.Variable, len(prefixBytes)),
		CurrTxPost:   make([]frontend.Variable, len(postFixBytes)),
		PrevTxId:     make([]frontend.Variable, len(prevTxnIdBytes)),
		CurrTxId:     make([]frontend.Variable, len(currTxId)),
	}

	for ndx := range prefixBytes {
		outerAssignment.CurrTxPrefix[ndx] = prefixBytes[ndx]
	}
	for ndx := range postFixBytes {
		outerAssignment.CurrTxPost[ndx] = postFixBytes[ndx]
	}
	for ndx := range prevTxnIdBytes {
		outerAssignment.PrevTxId[ndx] = prevTxnIdBytes[ndx]
	}
	for ndx := range currTxId {
		outerAssignment.CurrTxId[ndx] = currTxId[ndx]
	}

	return outerAssignment
}

func VerifyProof(genesisWitness witness.Witness, genesisProof native_groth16.Proof, verifyingKey native_groth16.VerifyingKey) bool {
	publicWitness, err := genesisWitness.Public()
	verifierOptions := groth16.GetNativeVerifierOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
	err = native_groth16.Verify(genesisProof, verifyingKey, publicWitness, verifierOptions)
	if err != nil {
		fmt.Printf("Fail on base case verification! %s\n", err)
		return false
	}
	return true
}

func ComputeProof(ccs *constraint.ConstraintSystem, provingKey *native_groth16.ProvingKey, outerWitness witness.Witness) (native_groth16.Proof, error) {

	proverOptions := groth16.GetNativeProverOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
	return native_groth16.Prove(*ccs, *provingKey, outerWitness, proverOptions)
}
