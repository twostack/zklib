package zklib

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	native_groth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/groth16"
	txivc "github.com/twostack/zklib/twostack/groth16"
	"math/big"
	"os"
)

type NormalProof struct {
	CurveId    ecc.ID
	InnerField *big.Int
	OuterField *big.Int

	verifierOptions backend.VerifierOption
	proverOptions   backend.ProverOption

	Ccs      *constraint.ConstraintSystem
	innerCcs *constraint.ConstraintSystem

	VerifyingKey *native_groth16.VerifyingKey
	ProvingKey   *native_groth16.ProvingKey

	BaseProofObj *BaseProof
}

func NewNormalProof(baseProof *BaseProof) (*NormalProof, error) {

	po := &NormalProof{}

	po.BaseProofObj = baseProof

	po.InnerField = txivc.InnerCurve.ScalarField()
	po.OuterField = txivc.OuterCurve.ScalarField()

	//IMPORTANT: Normal proof needs to read the OUTER field's curveId
	po.CurveId = txivc.OuterCurve

	po.verifierOptions = groth16.GetNativeVerifierOptions(po.OuterField, po.InnerField)
	po.proverOptions = groth16.GetNativeProverOptions(po.OuterField, po.InnerField)

	normalCcs, provingKey, verifyingKey, err := po.readSetupParams(po.InnerField, po.CurveId)

	if err != nil {
		return nil, err
	}

	po.Ccs = &normalCcs
	po.ProvingKey = &provingKey
	po.VerifyingKey = &verifyingKey

	return po, nil
}

func (po *NormalProof) SetupKeys() error {

	pk, vk, err := native_groth16.Setup(*po.Ccs)
	if err != nil {
		return err
	}

	po.VerifyingKey = &vk
	po.ProvingKey = &pk

	return nil
}

func (po *NormalProof) ComputeProof(fullWitness witness.Witness) (native_groth16.Proof, error) {
	return native_groth16.Prove(*po.Ccs, *po.ProvingKey, fullWitness, po.proverOptions)
}

func (po *NormalProof) CreateLightWitness(txId []byte) (*witness.Witness, error) {
	return txivc.CreateNormalLightWitness(txId, po.InnerField)
}

func (po *NormalProof) CreateFullWitness(
	prevPublicWitness witness.Witness,
	prevProof native_groth16.Proof,
	prevVk native_groth16.VerifyingKey,
	prefixBytes []byte, prevTxnIdBytes []byte, postFixBytes []byte, spendingTxId []byte) (*witness.Witness, error) {

	outerWitness, err := txivc.CreateNormalFullWitness(prevPublicWitness, prevProof, prevVk, prefixBytes, prevTxnIdBytes, postFixBytes, spendingTxId[:], po.OuterField)

	if err != nil {
		return nil, err
	}

	return &outerWitness, nil
}

func (po *NormalProof) createOuterAssignment(
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

	return outerAssignment
}

func (po *NormalProof) WriteKeys() error {
	err := writeKeys(*po.VerifyingKey, *po.ProvingKey, "norm_")
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

	po.ProvingKey = &pk
	po.VerifyingKey = &vk

	return nil
}

func (po *NormalProof) readSetupParams(outerField *big.Int, curveId ecc.ID) (constraint.ConstraintSystem, native_groth16.ProvingKey, native_groth16.VerifyingKey, error) {

	if _, err := os.Stat("normal_ccs.cbor"); errors.Is(err, os.ErrNotExist) {

		//setup normal case for base parent VK
		normalCcs, provingKey, verifyingKey, err := txivc.SetupNormalCase(outerField, *po.BaseProofObj.Ccs)

		//FIXME:
		//normalCcs, provingKey, verifyingKey, err := txivc.SetupNormalCase(outerField, *normalCcs)

		normalCcsFile, err := os.Create("norm_ccs.cbor")
		_, err = normalCcs.WriteTo(normalCcsFile)
		if err != nil {
			return nil, nil, nil, err
		}
		normalCcsFile.Close()

		err = writeKeys(verifyingKey, provingKey, "norm_")
		if err != nil {
			return nil, nil, nil, err
		}

		return normalCcs, provingKey, verifyingKey, nil
	} else {

		//in this portion we don't run Setup() again, because that generates different keys
		normalCcs, err := po.readCircuitParams()
		if err != nil {
			return nil, nil, nil, err
		}

		verifyingKey, provingKey, err := readKeys("norm_", curveId)
		if err != nil {
			return nil, nil, nil, err
		}

		return normalCcs, provingKey, verifyingKey, nil
	}
}

func (po *NormalProof) readCircuitParams() (constraint.ConstraintSystem, error) {

	normCcs := native_groth16.NewCS(txivc.InnerCurve)

	ccsFile, err := os.OpenFile("norm_ccs.cbor", os.O_RDONLY, 0444) //read-only
	if err != nil {
		return nil, err
	}
	_, err = normCcs.ReadFrom(ccsFile)
	if err != nil {
		return nil, err
	}
	ccsFile.Close()

	return normCcs, nil
}

func (po *NormalProof) VerifyProof(witness *witness.Witness, proof *native_groth16.Proof) bool {

	err := native_groth16.Verify(*proof, *po.VerifyingKey, *witness, po.verifierOptions)
	if err != nil {
		fmt.Printf("Fail on proof verification! %s\n", err)
		return false
	}
	return true
}