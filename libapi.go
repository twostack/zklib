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
	"log"
	"math/big"
	"os"
	"time"
	txivc "zklib/twostack/groth16"
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

	ccs          constraint.ConstraintSystem
	verifyingKey native_groth16.VerifyingKey
	provingKey   native_groth16.ProvingKey
}

type NormalProof struct {
	curveId    ecc.ID
	innerField *big.Int
	outerField *big.Int

	verifierOptions backend.VerifierOption
	proverOptions   backend.ProverOption

	ccs      constraint.ConstraintSystem
	innerCcs constraint.ConstraintSystem

	verifyingKey native_groth16.VerifyingKey
	provingKey   native_groth16.ProvingKey

	parentVerifyingKey native_groth16.VerifyingKey
}

func NewBaseProof() (*BaseProof, error) {

	po := &BaseProof{}

	po.innerField = ecc.BLS24_315.ScalarField()
	po.outerField = ecc.BW6_633.ScalarField()
	po.curveId = ecc.BLS24_315

	po.verifierOptions = groth16.GetNativeVerifierOptions(po.outerField, po.innerField)
	po.proverOptions = groth16.GetNativeProverOptions(po.outerField, po.innerField)

	ccs, err := frontend.Compile(po.innerField, r1cs.NewBuilder,
		&txivc.Sha256CircuitBaseCase[txivc.ScalarField, txivc.G1Affine, txivc.G2Affine, txivc.GTEl]{})
	if err != nil {
		return nil, err
	}

	po.ccs = ccs

	return po, nil
}

func (po *BaseProof) SetupKeys() error {

	if po.ccs == nil {
		return fmt.Errorf("No constraint system found. Please call New() first.")
	}

	innerPK, innerVK, err := native_groth16.Setup(po.ccs)

	if err != nil {
		return err
	}

	po.provingKey = innerPK
	po.verifyingKey = innerVK

	return nil
}

func (po *BaseProof) ComputeProof(witness witness.Witness) (
	native_groth16.Proof,
	error,
) {
	return native_groth16.Prove(po.ccs, po.provingKey, witness, po.proverOptions)
}

func (po *BaseProof) VerifyProof(witness witness.Witness, proof native_groth16.Proof) bool {
	publicWitness, err := witness.Public()
	err = native_groth16.Verify(proof, po.verifyingKey, publicWitness, po.verifierOptions)
	if err != nil {
		fmt.Printf("Fail on proof verification! %s\n", err)
		return false
	}
	return true
}

func (po *BaseProof) CreateBaseCaseWitness(
	prefixBytes []byte,
	postFixBytes []byte,
	prevTxnIdBytes []byte,
	currTxId [32]byte,
) (witness.Witness, error) {

	innerAssignment := txivc.Sha256CircuitBaseCase[txivc.ScalarField, txivc.G1Affine, txivc.G2Affine, txivc.GTEl]{}

	//assign the current Txn data
	copy(innerAssignment.CurrTxPrefix[:], uints.NewU8Array(prefixBytes))
	copy(innerAssignment.CurrTxPost[:], uints.NewU8Array(postFixBytes))
	copy(innerAssignment.PrevTxId[:], uints.NewU8Array(prevTxnIdBytes))
	copy(innerAssignment.CurrTxId[:], uints.NewU8Array(currTxId[:]))
	copy(innerAssignment.TokenId[:], uints.NewU8Array(currTxId[:])) //base case tokenId == txId

	innerWitness, err := frontend.NewWitness(&innerAssignment, po.innerField)

	if err != nil {
		return nil, err
	}
	return innerWitness, nil
}

func (*NormalProof) New(parentCcs constraint.ConstraintSystem, vk native_groth16.VerifyingKey) (*NormalProof, error) {

	po := &NormalProof{}

	po.verifierOptions = groth16.GetNativeVerifierOptions(po.outerField, po.innerField)
	po.proverOptions = groth16.GetNativeProverOptions(po.outerField, po.innerField)

	po.innerField = ecc.BLS24_315.ScalarField()
	po.outerField = ecc.BW6_633.ScalarField()
	po.curveId = ecc.BLS24_315

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

func (po *NormalProof) SetupKeys() (*NormalProof, error) {

	pk, vk, err := native_groth16.Setup(po.ccs)
	if err != nil {
		return nil, err
	}

	po.verifyingKey = vk
	po.provingKey = pk

	return po, nil
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

// generate innerVK, innerPK, compiled circuit and save to disk
func (po *BaseProof) WriteKeys() error {

	start := time.Now()
	innerVKFile, err := os.Create("vk.cbor")
	po.verifyingKey.WriteTo(innerVKFile)
	if err != nil {
		log.Fatal(err)
		return err
	}
	innerVKFile.Close()
	end := time.Since(start)
	fmt.Printf("Exporting Verifying Key took : %s\n", end)

	start = time.Now()
	innerPKFile, err := os.Create("pk.cbor")
	po.provingKey.WriteTo(innerPKFile)
	if err != nil {
		log.Fatal(err)
		return err
	}
	innerPKFile.Close()
	end = time.Since(start)
	fmt.Printf("Exporting Proving Key took : %s\n", end)

	return nil
}

func (po *BaseProof) ReadKeys() error {

	start := time.Now()
	innerVKFile, err := os.OpenFile("vk.cbor", os.O_RDONLY, 0444) //read-only
	if err != nil {
		log.Fatal(err)
		return err
	}
	innerVK := native_groth16.NewVerifyingKey(po.curveId) //curve for inner circuit
	po.verifyingKey = innerVK
	po.verifyingKey.ReadFrom(innerVKFile)
	innerVKFile.Close()
	end := time.Since(start)
	fmt.Printf("Importing Verifying Key took : %s\n", end)

	start = time.Now()
	innerPKFile, err := os.OpenFile("pk.cbor", os.O_RDONLY, 0444)
	if err != nil {
		log.Fatal(err)
		return err
	}
	innerPK := native_groth16.NewProvingKey(po.curveId) //curve for inner circuit
	po.provingKey = innerPK
	po.provingKey.ReadFrom(innerPKFile)
	innerPKFile.Close()
	end = time.Since(start)
	fmt.Printf("Importing Proving Key took : %s\n", end)

	return nil

}
