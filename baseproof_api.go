package zklib

import (
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	native_groth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/groth16"
	txivc "github.com/twostack/zklib/twostack/groth16"
	"math/big"
	"os"
)

type BaseProof struct {
	CurveId    ecc.ID
	InnerField *big.Int
	OuterField *big.Int

	verifierOptions backend.VerifierOption
	proverOptions   backend.ProverOption

	Ccs          *constraint.ConstraintSystem
	VerifyingKey *native_groth16.VerifyingKey
	ProvingKey   *native_groth16.ProvingKey
}

func NewBaseProof(baseTxSize int) (*BaseProof, error) {

	po := &BaseProof{}

	po.InnerField = txivc.InnerCurve.ScalarField()
	po.OuterField = txivc.OuterCurve.ScalarField()

	//IMPORTANT: Base proof needs to read the inner field's curveId
	po.CurveId = txivc.InnerCurve

	po.verifierOptions = groth16.GetNativeVerifierOptions(po.OuterField, po.InnerField)
	po.proverOptions = groth16.GetNativeProverOptions(po.OuterField, po.InnerField)

	baseCcs, provingKey, verifyingKey, err := readSetupParams(baseTxSize, po.InnerField, po.CurveId)

	//ccs, err := frontend.Compile(po.InnerField, r1cs.NewBuilder, baseTxCircuit)
	if err != nil {
		return nil, err
	}

	po.Ccs = &baseCcs
	po.ProvingKey = &provingKey
	po.VerifyingKey = &verifyingKey

	return po, nil
}

func readSetupParams(txSize int, innerField *big.Int, curveId ecc.ID) (constraint.ConstraintSystem, native_groth16.ProvingKey, native_groth16.VerifyingKey, error) {

	if _, err := os.Stat("base_2_ccs.cbor"); errors.Is(err, os.ErrNotExist) {

		baseCcs, provingKey, verifyingKey, err := txivc.SetupBaseCase(txSize, innerField)

		baseccsFile, err := os.Create("base_2_ccs.cbor")
		_, err = baseCcs.WriteTo(baseccsFile)
		if err != nil {
			return nil, nil, nil, err
		}
		baseccsFile.Close()

		err = writeKeys(verifyingKey, provingKey, "base_")
		if err != nil {
			return nil, nil, nil, err
		}

		return baseCcs, provingKey, verifyingKey, nil
	} else {

		//in this portion we don't run Setup() again, because that generates different keys
		baseCcs, err := readCircuitParams()
		if err != nil {
			return nil, nil, nil, err
		}

		verifyingKey, provingKey, err := readKeys("base_", curveId)
		if err != nil {
			return nil, nil, nil, err
		}

		return baseCcs, provingKey, verifyingKey, nil
	}
}

func readCircuitParams() (constraint.ConstraintSystem, error) {

	baseCcs := native_groth16.NewCS(txivc.InnerCurve)

	ccsFile, err := os.OpenFile("base_2_ccs.cbor", os.O_RDONLY, 0444) //read-only
	if err != nil {
		return nil, err
	}
	_, err = baseCcs.ReadFrom(ccsFile)
	if err != nil {
		return nil, err
	}
	ccsFile.Close()

	return baseCcs, nil
}

//func (po *BaseProof) SetupKeys() error {
//
//	if po.Ccs == nil {
//		return fmt.Errorf("No constraint system found. Please call New() first.")
//	}
//
//	innerPK, innerVK, err := native_groth16.Setup(*po.Ccs)
//
//	if err != nil {
//		return err
//	}
//
//	po.ProvingKey = &innerPK
//	po.VerifyingKey = &innerVK
//
//	return nil
//}

func (po *BaseProof) ComputeProof(fullWitness witness.Witness) (
	native_groth16.Proof,
	error,
) {
	return native_groth16.Prove(*po.Ccs, *po.ProvingKey, fullWitness, po.proverOptions)
}

func (po *BaseProof) VerifyProof(witness *witness.Witness, proof *native_groth16.Proof) bool {
	err := native_groth16.Verify(*proof, *po.VerifyingKey, *witness, po.verifierOptions)
	if err != nil {
		fmt.Printf("Fail on proof verification! %s\n", err)
		return false
	}
	return true
}

func (po *BaseProof) CreateBaseCaseWitness(
	rawTxBytes []byte,
	currTxId [32]byte,
) (witness.Witness, error) {

	innerAssignment := txivc.Sha256CircuitBaseCase[txivc.ScalarField, txivc.G1Affine, txivc.G2Affine, txivc.GTEl]{
		RawTx: make([]frontend.Variable, len(rawTxBytes)),
	}

	//assign the current Txn data
	//assign the current Txn data
	for ndx, entry := range rawTxBytes {
		innerAssignment.RawTx[ndx] = entry
	}
	//copy(innerAssignment.RawTx[:], uints.NewU8Array(rawTxBytes))
	copy(innerAssignment.CurrTxId[:], uints.NewU8Array(currTxId[:]))
	//copy(innerAssignment.TokenId[:], uints.NewU8Array(currTxId[:])) //base case tokenId == txId

	innerWitness, err := frontend.NewWitness(&innerAssignment, po.InnerField)

	if err != nil {
		return nil, err
	}
	return innerWitness, nil
}

// generate innerVK, innerPK, compiled circuit and save to disk
func (po *BaseProof) WriteKeys() error {
	err := writeKeys(*po.VerifyingKey, *po.ProvingKey, "base_")
	if err != nil {
		return err
	}

	return nil
}

func (po *BaseProof) ReadKeys() error {
	vk, pk, err := readKeys("base_", po.CurveId)

	if err != nil {
		return err
	}

	po.ProvingKey = &pk
	po.VerifyingKey = &vk

	return nil
}
