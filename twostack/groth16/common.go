package txivc

import (
	"crypto/sha256"
	native_groth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
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

	baseCcs, err := frontend.Compile(innerField, scs.NewBuilder,
		&Sha256CircuitBaseCase[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{})

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

func CreateBaseCaseProof(outerField, innerField *big.Int, fullTxBytes []byte, prefixBytes []byte, prevTxnIdBytes []byte, postfixBytes []byte, innerCcs constraint.ConstraintSystem, provingKey native_groth16.ProvingKey) (
	witness.Witness,
	native_groth16.Proof,
	error,
) {

	firstHash := sha256.Sum256(fullTxBytes)
	genesisTxId := sha256.Sum256(firstHash[:])

	genesisWitness, err := CreateBaseCaseWitness(prefixBytes, postfixBytes, prevTxnIdBytes, genesisTxId, innerField)
	if err != nil {
		return nil, nil, err
	}

	proof, err := native_groth16.Prove(innerCcs, provingKey, genesisWitness, groth16.GetNativeProverOptions(outerField, innerField))

	return genesisWitness, proof, err
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
