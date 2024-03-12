package txivc

import (
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark/backend"
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

//type ScalarField = sw_bls12377.ScalarField
//type G1Affine = sw_bls12377.G1Affine
//type G2Affine = sw_bls12377.G2Affine
//type GTEl = sw_bls12377.GT

type ScalarField = sw_bls24315.ScalarField
type G1Affine = sw_bls24315.G1Affine
type G2Affine = sw_bls24315.G2Affine
type GTEl = sw_bls24315.GT

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

func SetupBaseCase(innerField *big.Int) (constraint.ConstraintSystem, native_groth16.ProvingKey, native_groth16.VerifyingKey, error) {

	baseCcs, err := frontend.Compile(innerField, r1cs.NewBuilder,
		&Sha256CircuitBaseCase[ScalarField, G1Affine, G2Affine, GTEl]{})

	if err != nil {
		return nil, nil, nil, err
	}

	innerPK, innerVK, err := native_groth16.Setup(baseCcs)
	if err != nil {
		return nil, nil, nil, err
	}
	return baseCcs, innerPK, innerVK, nil
}

func SetupNormalCase(outerField *big.Int, parentCcs constraint.ConstraintSystem, parentVk groth16.VerifyingKey[G1Affine, G2Affine, GTEl]) (constraint.ConstraintSystem, native_groth16.ProvingKey, native_groth16.VerifyingKey, error) {

	innerCcs, err := frontend.Compile(outerField, r1cs.NewBuilder,
		&Sha256Circuit[ScalarField, G1Affine, G2Affine, GTEl]{
			PreviousProof:   groth16.PlaceholderProof[G1Affine, G2Affine](parentCcs),
			PreviousVk:      parentVk,
			PreviousWitness: groth16.PlaceholderWitness[ScalarField](parentCcs),
		})

	if err != nil {
		return nil, nil, nil, err
	}

	innerPK, innerVK, err := native_groth16.Setup(innerCcs)
	if err != nil {
		return nil, nil, nil, err
	}
	return innerCcs, innerPK, innerVK, nil
}

func CreateBaseCaseProof(proverOptions backend.ProverOption, innerCcs constraint.ConstraintSystem, genesisWitness witness.Witness, provingKey native_groth16.ProvingKey) (
	native_groth16.Proof,
	error,
) {
	return native_groth16.Prove(innerCcs, provingKey, genesisWitness, proverOptions)
}

func CreateBaseCaseWitness(
	prefixBytes []byte,
	postFixBytes []byte,
	prevTxnIdBytes []byte,
	currTxId [32]byte,
	innerField *big.Int,
) (witness.Witness, error) {

	innerAssignment := Sha256CircuitBaseCase[ScalarField, G1Affine, G2Affine, GTEl]{}

	//assign the current Txn data
	copy(innerAssignment.CurrTxPrefix[:], uints.NewU8Array(prefixBytes))
	copy(innerAssignment.CurrTxPost[:], uints.NewU8Array(postFixBytes))
	copy(innerAssignment.PrevTxId[:], uints.NewU8Array(prevTxnIdBytes))
	copy(innerAssignment.CurrTxId[:], uints.NewU8Array(currTxId[:]))
	copy(innerAssignment.TokenId[:], uints.NewU8Array(currTxId[:])) //base case tokenId == txId

	innerWitness, err := frontend.NewWitness(&innerAssignment, innerField)
	if err != nil {
		return nil, err
	}
	return innerWitness, nil
}

func CreateOuterAssignment(
	circuitWitness groth16.Witness[ScalarField],
	circuitProof groth16.Proof[G1Affine, G2Affine],
	verifyingKey groth16.VerifyingKey[G1Affine, G2Affine, GTEl],
	prefixBytes []byte, prevTxnIdBytes []byte, postFixBytes []byte, fullTxBytes []byte) Sha256Circuit[ScalarField, G1Affine, G2Affine, GTEl] {

	outerAssignment := Sha256Circuit[ScalarField, G1Affine, G2Affine, GTEl]{
		PreviousWitness: circuitWitness,
		PreviousProof:   circuitProof,
		PreviousVk:      verifyingKey,
	}

	firstHash := sha256.Sum256(fullTxBytes)
	currTxId := sha256.Sum256(firstHash[:])

	copy(outerAssignment.CurrTxPrefix[:], uints.NewU8Array(prefixBytes))
	copy(outerAssignment.CurrTxPost[:], uints.NewU8Array(postFixBytes))
	copy(outerAssignment.PrevTxId[:], uints.NewU8Array(prevTxnIdBytes))
	copy(outerAssignment.CurrTxId[:], uints.NewU8Array(currTxId[:]))

	tokenId := [32]byte{}
	copy(tokenId[:], prevTxnIdBytes)
	copy(outerAssignment.TokenId[:], uints.NewU8Array(tokenId[:]))

	return outerAssignment
}

func VerifyProof(genesisWitness witness.Witness, genesisProof native_groth16.Proof, verifyingKey native_groth16.VerifyingKey, verifierOptions backend.VerifierOption) bool {
	publicWitness, err := genesisWitness.Public()
	err = native_groth16.Verify(genesisProof, verifyingKey, publicWitness, verifierOptions)
	if err != nil {
		fmt.Printf("Fail on base case verification! %s\n", err)
		return false
	}
	return true
}

func ComputeProof(outerCcs constraint.ConstraintSystem, outerProvingKey native_groth16.ProvingKey, outerWitness witness.Witness, proverOptions backend.ProverOption) (native_groth16.Proof, error) {
	return native_groth16.Prove(outerCcs, outerProvingKey, outerWitness, proverOptions)
}
