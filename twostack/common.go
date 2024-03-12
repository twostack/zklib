package twostack

import (
	"crypto/sha256"
	native_groth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls24315"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/groth16"
	"math/big"
)

// type ScalarField = sw_bls24315.ScalarField
// type G1Affine = sw_bls24315.G1Affine
// type G2Affine = sw_bls24315.G2Affine
// type GTEl = sw_bls24315.GT
//type ScalarField = sw_bls12381.ScalarField
//type G1Affine = sw_bls12381.G1Affine
//type G2Affine = sw_bls12381.G2Affine
//type GTEl = sw_bls12381.GTEl

// type ScalarField = sw_bn254.ScalarField
// type G1Affine = sw_bn254.G1Affine
// type G2Affine = sw_bn254.G2Affine
// type GTEl = sw_bn254.GTEl
type ScalarField = sw_bls24315.ScalarField
type G1Affine = sw_bls24315.G1Affine
type G2Affine = sw_bls24315.G2Affine
type GTEl = sw_bls24315.GT

func SetupBaseCase(innerField *big.Int) (constraint.ConstraintSystem, native_groth16.ProvingKey, native_groth16.VerifyingKey, error) {

	baseCcs, err := frontend.Compile(innerField, r1cs.NewBuilder,
		&SigCircuitBaseCase[ScalarField, G1Affine, G2Affine, GTEl]{})

	if err != nil {
		return nil, nil, nil, err
	}

	//srs, srsLagrange, err := unsafekzg.NewSRS(baseCcs)

	if err != nil {
		return nil, nil, nil, err
	}

	innerPK, innerVK, err := native_groth16.Setup(baseCcs)
	if err != nil {
		return nil, nil, nil, err
	}
	return baseCcs, innerPK, innerVK, nil
}

func SetupNormalCase(
	outerField *big.Int,
	parentCcs constraint.ConstraintSystem,
	parentVk groth16.VerifyingKey[G1Affine, G2Affine, GTEl]) (constraint.ConstraintSystem, native_groth16.ProvingKey, native_groth16.VerifyingKey, error) {

	innerCcs, err := frontend.Compile(outerField, r1cs.NewBuilder,
		&SigCircuit[ScalarField, G1Affine, G2Affine, GTEl]{
			PreviousProof:   groth16.PlaceholderProof[G1Affine, G2Affine](parentCcs),
			PreviousVk:      parentVk,
			PreviousWitness: groth16.PlaceholderWitness[ScalarField](parentCcs),
		})

	if err != nil {
		return nil, nil, nil, err
	}

	//srs, srsLagrange, err := unsafekzg.NewSRS(innerCcs)

	if err != nil {
		return nil, nil, nil, err
	}

	innerPK, innerVK, err := native_groth16.Setup(innerCcs)
	if err != nil {
		return nil, nil, nil, err
	}
	return innerCcs, innerPK, innerVK, nil
}

func CreateBaseCaseProof(outerField, innerField *big.Int, fullTxBytes []byte, txnIdBytes [32]byte, innerCcs constraint.ConstraintSystem, provingKey native_groth16.ProvingKey) (
	witness.Witness,
	native_groth16.Proof,
	error,
) {

	genesisWitness, err := CreateBaseCaseWitness(fullTxBytes, innerField)
	if err != nil {
		return nil, nil, err
	}

	proof, err := native_groth16.Prove(innerCcs, provingKey, genesisWitness, groth16.GetNativeProverOptions(outerField, innerField))

	return genesisWitness, proof, err
}

func CreateBaseCaseWitness(
	fullTxBytes []byte,
	innerField *big.Int,
) (witness.Witness, error) {

	innerAssignment := SigCircuitBaseCase[ScalarField, G1Affine, G2Affine, GTEl]{}

	firstHash := sha256.Sum256(fullTxBytes)

	//assign the current Txn data
	copy(innerAssignment.TxPreImage[:], uints.NewU8Array(fullTxBytes))
	copy(innerAssignment.ImageHash[:], uints.NewU8Array(firstHash[:]))

	innerWitness, err := frontend.NewWitness(&innerAssignment, innerField)
	if err != nil {
		return nil, err
	}
	return innerWitness, nil
}

/*
func CreateOuterAssignment(
	circuitWitness plonk.Witness[sw_bls12377.ScalarField],
	circuitProof groth16_bls24315.Proof,
	verifyingKey groth16_bls24315.VerifyingKey,
	fullTxBytes []byte, tokenId [32]byte) SigCircuit[ScalarField, G1Affine, G2Affine, GTEl] {

	outerAssignment := SigCircuit[ScalarField, G1Affine, G2Affine, GTEl]{
		PreviousProof: circuitProof,
		PreviousVk:    verifyingKey,
	}

	firstHash := sha256.Sum256(fullTxBytes)
	//currTxId := sha256.Sum256(firstHash[:])

	copy(outerAssignment.TxPreImage[:], uints.NewU8Array(fullTxBytes))
	copy(outerAssignment.ImageHash[:], uints.NewU8Array(firstHash[:]))

	return outerAssignment
}

*/
