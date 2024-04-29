package zklib

import (
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	native_groth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/groth16"
	txivc "github.com/twostack/zklib/twostack/groth16"
	"log"
	"math/big"
	"os"
	"time"
)

/*
PreviousProof object to encapsulate the behaviour of
doing setup just once, and then repeatedly
constructing and verifying proofs and
*/
type BaseProof struct {
	curveId    ecc.ID
	innerField *big.Int
	outerField *big.Int

	verifierOptions backend.VerifierOption
	proverOptions   backend.ProverOption

	Ccs          constraint.ConstraintSystem
	VerifyingKey native_groth16.VerifyingKey
	ProvingKey   native_groth16.ProvingKey
}

type NormalProof struct {
	curveId    ecc.ID
	innerField *big.Int
	outerField *big.Int

	verifierOptions backend.VerifierOption
	proverOptions   backend.ProverOption

	ccs      constraint.ConstraintSystem
	innerCcs constraint.ConstraintSystem

	VerifyingKey native_groth16.VerifyingKey
	ProvingKey   native_groth16.ProvingKey

	ParentVerifyingKey native_groth16.VerifyingKey
}

func NewBaseProof() (*BaseProof, error) {

	po := &BaseProof{}

	po.innerField = ecc.BLS24_315.ScalarField()
	po.outerField = ecc.BW6_633.ScalarField()

	//IMPORTANT: Base proof needs to read the inner field's curveId
	po.curveId = ecc.BLS24_315

	po.verifierOptions = groth16.GetNativeVerifierOptions(po.outerField, po.innerField)
	po.proverOptions = groth16.GetNativeProverOptions(po.outerField, po.innerField)

	ccs, err := frontend.Compile(po.innerField, r1cs.NewBuilder,
		&txivc.Sha256CircuitBaseCase[txivc.ScalarField, txivc.G1Affine, txivc.G2Affine, txivc.GTEl]{})
	if err != nil {
		return nil, err
	}

	po.Ccs = ccs

	return po, nil
}

func (po *BaseProof) SetupKeys() error {

	if po.Ccs == nil {
		return fmt.Errorf("No constraint system found. Please call New() first.")
	}

	innerPK, innerVK, err := native_groth16.Setup(po.Ccs)

	if err != nil {
		return err
	}

	po.ProvingKey = innerPK
	po.VerifyingKey = innerVK

	return nil
}

func (po *BaseProof) ComputeProof(witness witness.Witness) (
	native_groth16.Proof,
	error,
) {
	return native_groth16.Prove(po.Ccs, po.ProvingKey, witness, po.proverOptions)
}

func (po *BaseProof) VerifyProof(witness witness.Witness, proof native_groth16.Proof) bool {
	publicWitness, err := witness.Public()
	err = native_groth16.Verify(proof, po.VerifyingKey, publicWitness, po.verifierOptions)
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
	copy(innerAssignment.TokenId[:], uints.NewU8Array(currTxId[:])) //base case tokenId == txId

	innerWitness, err := frontend.NewWitness(&innerAssignment, po.innerField)

	if err != nil {
		return nil, err
	}
	return innerWitness, nil
}

// generate innerVK, innerPK, compiled circuit and save to disk
func (po *BaseProof) WriteKeys() error {
	err := writeKeys(po.VerifyingKey, po.ProvingKey, "base_")
	if err != nil {
		return err
	}

	return nil
}

func (po *BaseProof) ReadKeys() error {
	vk, pk, err := readKeys("base_", po.curveId)

	if err != nil {
		return err
	}

	po.ProvingKey = pk
	po.VerifyingKey = vk

	return nil
}

/**
--------------------------------
Normal Proof methods]
-------------------------------
*/

func NewNormalProof(parentCcs constraint.ConstraintSystem, vk native_groth16.VerifyingKey) (*NormalProof, error) {

	po := &NormalProof{}

	po.verifierOptions = groth16.GetNativeVerifierOptions(po.outerField, po.innerField)
	po.proverOptions = groth16.GetNativeProverOptions(po.outerField, po.innerField)

	po.innerField = ecc.BLS24_315.ScalarField()
	po.outerField = ecc.BW6_633.ScalarField()

	//IMPORTANT: Normal proof needs to read the OUTER field's curveId
	po.curveId = ecc.BW6_633

	parentVk, err := groth16.ValueOfVerifyingKey[txivc.G1Affine, txivc.G2Affine, txivc.GTEl](vk)
	if err != nil {
		return nil, err
	}

	innerCcs, err := frontend.Compile(po.outerField, r1cs.NewBuilder,
		&txivc.Sha256Circuit[txivc.ScalarField, txivc.G1Affine, txivc.G2Affine, txivc.GTEl]{
			PreviousProof:   groth16.PlaceholderProof[txivc.G1Affine, txivc.G2Affine](parentCcs),
			PreviousVk:      parentVk,
			PreviousWitness: groth16.PlaceholderWitness[txivc.ScalarField](parentCcs),
		})

	if err != nil {
		return nil, err
	}

	po.ccs = innerCcs

	return po, nil
}

func (po *NormalProof) SetupKeys() error {

	pk, vk, err := native_groth16.Setup(po.ccs)
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

	tokenId := [32]byte{}
	copy(tokenId[:], prevTxnIdBytes)
	copy(outerAssignment.TokenId[:], uints.NewU8Array(tokenId[:]))

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
	vk, pk, err := readKeys("norm_", po.curveId)

	if err != nil {
		return err
	}

	po.ProvingKey = pk
	po.VerifyingKey = vk

	return nil
}

func writeKeys(verifyingKey native_groth16.VerifyingKey, provingKey native_groth16.ProvingKey, prefix string) error {

	start := time.Now()
	innerVKFile, err := os.Create(prefix + "vk.cbor")
	_, err = verifyingKey.WriteRawTo(innerVKFile)
	if err != nil {
		return fmt.Errorf("Failed to write Verifying Key - ", err)
	}
	err = innerVKFile.Close()
	if err != nil {
		return fmt.Errorf("Failed to close verifying key file handle  - ", err)
	}
	end := time.Since(start)
	fmt.Printf("Exporting Verifying Key took : %s\n", end)

	start = time.Now()
	innerPKFile, err := os.Create(prefix + "pk.cbor")
	_, err = provingKey.WriteRawTo(innerPKFile)
	if err != nil {
		return fmt.Errorf("Failed to write Proving Key - ", err)
	}
	err = innerPKFile.Close()
	if err != nil {
		return fmt.Errorf("Failed to properly close Proving Key File handle - ", err)
	}
	end = time.Since(start)
	fmt.Printf("Exporting Proving Key took : %s\n", end)
	return nil
}

func readKeys(prefix string, curveId ecc.ID) (native_groth16.VerifyingKey, native_groth16.ProvingKey, error) {

	start := time.Now()
	innerVKFile, err := os.OpenFile(prefix+"vk.cbor", os.O_RDONLY, 0444) //read-only
	if err != nil {
		log.Fatal(err)
		return nil, nil, err
	}
	innerVK := native_groth16.NewVerifyingKey(curveId) //curve for inner circuit
	_, err = innerVK.ReadFrom(innerVKFile)
	if err != nil {
		log.Fatal(err)
		return nil, nil, err
	}
	innerVKFile.Close()
	end := time.Since(start)
	fmt.Printf("Importing Verifying Key took : %s\n", end)

	start = time.Now()
	innerPKFile, err := os.OpenFile(prefix+"pk.cbor", os.O_RDONLY, 0444)
	if err != nil {
		log.Fatal(err)
		return nil, nil, err
	}
	innerPK := native_groth16.NewProvingKey(curveId) //curve for inner circuit
	_, err = innerPK.ReadFrom(innerPKFile)
	if err != nil {
		log.Fatal(err)
		return nil, nil, err
	}

	innerPKFile.Close()
	end = time.Since(start)
	fmt.Printf("Importing Proving Key took : %s\n", end)

	return innerVK, innerPK, nil
}
