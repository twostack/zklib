package twostack

import (
	"crypto/sha256"
	"github.com/consensys/gnark-crypto/ecc"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
	"math/big"
)

func SetupBaseCase(innerField *big.Int) (constraint.ConstraintSystem, native_plonk.ProvingKey, native_plonk.VerifyingKey, error) {

	baseCcs, err := frontend.Compile(innerField, scs.NewBuilder,
		&SigCircuitBaseCase[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{})

	if err != nil {
		return nil, nil, nil, err
	}

	srs, srsLagrange, err := unsafekzg.NewSRS(baseCcs)

	if err != nil {
		return nil, nil, nil, err
	}

	innerPK, innerVK, err := native_plonk.Setup(baseCcs, srs, srsLagrange)
	if err != nil {
		return nil, nil, nil, err
	}
	return baseCcs, innerPK, innerVK, nil
}

func SetupNormalCase(outerField *big.Int, parentCcs constraint.ConstraintSystem, parentVk plonk.VerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine]) (constraint.ConstraintSystem, native_plonk.ProvingKey, native_plonk.VerifyingKey, error) {

	innerCcs, err := frontend.Compile(outerField, scs.NewBuilder,
		&SigCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
			PreviousProof:   plonk.PlaceholderProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](parentCcs),
			PreviousVk:      parentVk,
			PreviousWitness: plonk.PlaceholderWitness[sw_bls12377.ScalarField](parentCcs),
		})

	if err != nil {
		return nil, nil, nil, err
	}

	srs, srsLagrange, err := unsafekzg.NewSRS(innerCcs)

	if err != nil {
		return nil, nil, nil, err
	}

	innerPK, innerVK, err := native_plonk.Setup(innerCcs, srs, srsLagrange)
	if err != nil {
		return nil, nil, nil, err
	}
	return innerCcs, innerPK, innerVK, nil
}

func CreateBaseCaseProof(fullTxBytes []byte, prevTxnIdBytes [32]byte, innerCcs constraint.ConstraintSystem, provingKey native_plonk.ProvingKey) (
	witness.Witness,
	native_plonk.Proof,
	error,
) {

	innerField := ecc.BLS12_377.ScalarField()
	outerField := ecc.BW6_761.ScalarField()

	genesisWitness, err := CreateBaseCaseWitness(fullTxBytes, prevTxnIdBytes)
	if err != nil {
		return nil, nil, err
	}

	proof, err := native_plonk.Prove(innerCcs, provingKey, genesisWitness, plonk.GetNativeProverOptions(outerField, innerField))

	return genesisWitness, proof, err
}

func CreateBaseCaseWitness(
	fullTxBytes []byte,
	currTxId [32]byte,
) (witness.Witness, error) {

	innerAssignment := SigCircuitBaseCase[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{}

	//assign the current Txn data
	copy(innerAssignment.TxPreImage[:], uints.NewU8Array(fullTxBytes))
	copy(innerAssignment.CurrTxId[:], uints.NewU8Array(currTxId[:]))
	copy(innerAssignment.TokenId[:], uints.NewU8Array(currTxId[:])) //base case tokenId == txId

	innerWitness, err := frontend.NewWitness(&innerAssignment, ecc.BLS12_377.ScalarField())
	if err != nil {
		return nil, err
	}
	return innerWitness, nil
}

func CreateOuterAssignment(
	circuitWitness plonk.Witness[sw_bls12377.ScalarField],
	circuitProof plonk.Proof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine],
	verifyingKey plonk.VerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine],
	fullTxBytes []byte, tokenId [32]byte) SigCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT] {

	outerAssignment := SigCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		PreviousWitness: circuitWitness,
		PreviousProof:   circuitProof,
		PreviousVk:      verifyingKey,
	}

	firstHash := sha256.Sum256(fullTxBytes)
	currTxId := sha256.Sum256(firstHash[:])

	copy(outerAssignment.TxPreImage[:], uints.NewU8Array(fullTxBytes))
	copy(outerAssignment.CurrTxId[:], uints.NewU8Array(currTxId[:]))
	copy(outerAssignment.TokenId[:], uints.NewU8Array(tokenId[:]))

	return outerAssignment
}
