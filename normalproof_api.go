package zklib

import (
	"crypto/sha256"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	native_groth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/groth16"
	txivc "github.com/twostack/zklib/twostack/groth16"
	"math/big"
)

type NormalProof struct {
	CurveId    ecc.ID
	InnerField *big.Int
	OuterField *big.Int

	verifierOptions backend.VerifierOption
	proverOptions   backend.ProverOption

	Ccs      constraint.ConstraintSystem
	innerCcs constraint.ConstraintSystem

	VerifyingKey native_groth16.VerifyingKey
	ProvingKey   native_groth16.ProvingKey

	ParentVerifyingKey native_groth16.VerifyingKey
}

/**
--------------------------------
Normal Proof methods]
-------------------------------
*/

func NewNormalProof(parentCcs *constraint.ConstraintSystem, vk *native_groth16.VerifyingKey) (*NormalProof, error) {

	//innerCcs, err := frontend.Compile(outerField, r1cs.NewBuilder,
	//	&Sha256Circuit[ScalarField, G1Affine, G2Affine, GTEl]{
	//		PreviousProof:   groth16.PlaceholderProof[G1Affine, G2Affine](parentCcs),
	//		PreviousVk:      parentVk,
	//		PreviousWitness: groth16.PlaceholderWitness[ScalarField](parentCcs),
	//	})
	//
	//if err != nil {
	//	return nil, nil, nil, err
	//}
	//
	//innerPK, innerVK, err := native_groth16.Setup(innerCcs)
	//if err != nil {
	//	return nil, nil, nil, err
	//}
	//return innerCcs, innerPK, innerVK, nil

	po := &NormalProof{}

	po.InnerField = txivc.InnerCurve.ScalarField()
	po.OuterField = txivc.OuterCurve.ScalarField()

	po.verifierOptions = groth16.GetNativeVerifierOptions(po.OuterField, po.InnerField)
	po.proverOptions = groth16.GetNativeProverOptions(po.OuterField, po.InnerField)

	//IMPORTANT: Normal proof needs to read the OUTER field's curveId
	po.CurveId = txivc.OuterCurve

	parentVk, err := groth16.ValueOfVerifyingKey[txivc.G1Affine, txivc.G2Affine, txivc.GTEl](*vk)
	if err != nil {
		return nil, err
	}

	innerCcs, err := frontend.Compile(po.OuterField, r1cs.NewBuilder,
		&txivc.Sha256Circuit[txivc.ScalarField, txivc.G1Affine, txivc.G2Affine, txivc.GTEl]{
			PreviousProof:   groth16.PlaceholderProof[txivc.G1Affine, txivc.G2Affine](*parentCcs),
			PreviousVk:      parentVk,
			PreviousWitness: groth16.PlaceholderWitness[txivc.ScalarField](*parentCcs),
		})

	if err != nil {
		return nil, err
	}

	po.Ccs = innerCcs

	return po, nil
}

func (po *NormalProof) SetupKeys() error {

	pk, vk, err := native_groth16.Setup(po.Ccs)
	if err != nil {
		return err
	}

	po.VerifyingKey = vk
	po.ProvingKey = pk

	return nil
}

func (po *NormalProof) CreateOuterAssignment(
	circuitWitness groth16.Witness[txivc.ScalarField],
	circuitProof groth16.Proof[txivc.G1Affine, txivc.G2Affine],
	verifyingKey groth16.VerifyingKey[txivc.G1Affine, txivc.G2Affine, txivc.GTEl],
	prefixBytes []byte, prevTxnIdBytes []byte, postFixBytes []byte, fullTxBytes []byte) txivc.Sha256Circuit[txivc.ScalarField, txivc.G1Affine, txivc.G2Affine, txivc.GTEl] {

	outerAssignment := txivc.Sha256Circuit[txivc.ScalarField, txivc.G1Affine, txivc.G2Affine, txivc.GTEl]{
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

	//tokenId := [32]byte{}
	//copy(tokenId[:], prevTxnIdBytes)
	//copy(outerAssignment.TokenId[:], uints.NewU8Array(tokenId[:]))

	return outerAssignment
}

func (po *NormalProof) WriteKeys() error {
	err := writeKeys(po.VerifyingKey, po.ProvingKey, "norm_")
	if err != nil {
		return err
	}

	return nil
}

func (po *NormalProof) ReadKeys() error {
	vk, pk, err := readKeys("norm_", po.CurveId)

	if err != nil {
		return err
	}

	po.ProvingKey = pk
	po.VerifyingKey = vk

	return nil
}
