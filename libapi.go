package zklib

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"github.com/libsv/go-bt"
	txivc "github.com/twostack/zklib/twostack/groth16"
	"io"
	"log"
	"math/big"
	"os"
	"time"
)

var baseProof *BaseProof
var normalProof *NormalProof

/*
PreviousProof object to encapsulate the behaviour of
doing setup just once, and then repeatedly
constructing and verifying proofs and
*/
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

func NewBaseProof(baseTxSize int) (*BaseProof, error) {

	po := &BaseProof{}

	po.InnerField = txivc.InnerCurve.ScalarField()
	po.OuterField = txivc.OuterCurve.ScalarField()

	//IMPORTANT: Base proof needs to read the inner field's curveId
	po.CurveId = txivc.InnerCurve

	po.verifierOptions = groth16.GetNativeVerifierOptions(po.OuterField, po.InnerField)
	po.proverOptions = groth16.GetNativeProverOptions(po.OuterField, po.InnerField)

	baseTxCircuit := &txivc.Sha256CircuitBaseCase[txivc.ScalarField, txivc.G1Affine, txivc.G2Affine, txivc.GTEl]{
		RawTx: make([]frontend.Variable, baseTxSize),
	}

	ccs, err := frontend.Compile(po.InnerField, r1cs.NewBuilder, baseTxCircuit)
	if err != nil {
		return nil, err
	}

	po.Ccs = &ccs

	return po, nil
}

func (po *BaseProof) SetupKeys() error {

	if po.Ccs == nil {
		return fmt.Errorf("No constraint system found. Please call New() first.")
	}

	innerPK, innerVK, err := native_groth16.Setup(*po.Ccs)

	if err != nil {
		return err
	}

	po.ProvingKey = &innerPK
	po.VerifyingKey = &innerVK

	return nil
}

func (po *BaseProof) ComputeProof(witness witness.Witness) (
	native_groth16.Proof,
	error,
) {
	return native_groth16.Prove(*po.Ccs, *po.ProvingKey, witness, po.proverOptions)
}

func (po *BaseProof) VerifyProof(witness witness.Witness, proof native_groth16.Proof) bool {
	publicWitness, err := witness.Public()
	err = native_groth16.Verify(proof, *po.VerifyingKey, publicWitness, po.verifierOptions)
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

func writeKeys(verifyingKey native_groth16.VerifyingKey, provingKey native_groth16.ProvingKey, prefix string) error {

	start := time.Now()
	innerVKFile, err := os.Create(prefix + "vk.cbor")
	_, err = verifyingKey.WriteRawTo(innerVKFile)
	if err != nil {
		return fmt.Errorf("Failed to write Verifying Key - %s", err)
	}
	err = innerVKFile.Close()
	if err != nil {
		return fmt.Errorf("Failed to close verifying key file handle  - %s", err)
	}
	end := time.Since(start)
	fmt.Printf("Exporting Verifying Key took : %s\n", end)

	start = time.Now()
	innerPKFile, err := os.Create(prefix + "pk.cbor")
	_, err = provingKey.WriteRawTo(innerPKFile)
	if err != nil {
		return fmt.Errorf("Failed to write Proving Key - %s", err)
	}
	err = innerPKFile.Close()
	if err != nil {
		return fmt.Errorf("Failed to properly close Proving Key File handle - %s", err)
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

func CreateNormalCaseProof(normalInfo *txivc.NormalProofInfo) (string, error) {
	//outerAssignment := normalProof.CreateOuterAssignment()

	var prevTxCcs constraint.ConstraintSystem
	var prevTxVk native_groth16.VerifyingKey

	var prevTxWitness witness.Witness
	var prevTxProof native_groth16.Proof

	fullTxBytes, err := hex.DecodeString(normalInfo.RawTx)
	if err != nil {
		return "", err
	}

	prefixBytes, prevTxnId, postfixBytes, err := SliceTx(fullTxBytes, normalInfo.InputIndex)

	firstHash := sha256.Sum256(fullTxBytes)
	currTxId := sha256.Sum256(firstHash[:])

	//initialize params based on whether our previous txn was a base case of normal case
	if normalInfo.IsParentBase {
		prevTxCcs = *baseProof.Ccs
		prevTxVk = *baseProof.VerifyingKey
		prevTxProof = native_groth16.NewProof(baseProof.CurveId)
		prevTxWitness, err = txivc.CreateBaseCaseLightWitness(currTxId[:], normalProof.InnerField)
		if err != nil {
			return "", err
		}

	} else {
		prevTxCcs = normalProof.Ccs
		prevTxVk = normalProof.VerifyingKey
		prevTxProof = native_groth16.NewProof(normalProof.CurveId)
		prevTxWitness, err = txivc.CreateNormalLightWitness(currTxId[:], normalProof.InnerField)
		if err != nil {
			return "", err
		}
	}

	var innerProofBytes = []byte(normalInfo.Proof)
	err = json.Unmarshal(innerProofBytes, &prevTxProof)
	if err != nil {
		//log.Error().Msg(fmt.Sprintf("Error unmarshalling proof : [%s]\n", err.Error()))
		return "", err
	}

	normalWitness, err := txivc.CreateNormalFullWitness(
		prevTxWitness,
		prevTxProof,
		prevTxVk,
		prefixBytes,
		prevTxnId,
		postfixBytes,
		fullTxBytes,
		normalProof.OuterField,
	)
	if err != nil {
		return "", err
	}

	resultProof, err := txivc.ComputeProof(&prevTxCcs, &normalProof.ProvingKey, normalWitness)
	if err != nil {
		//log.Error().Msg(fmt.Sprintf("Error computing proof : [%s]\n", err.Error()))
		return "", err
	}

	jsonBytes, err := json.Marshal(resultProof)

	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}

var BASE_RAW_TX_SIZE = 191

func bootBaseProof() (*BaseProof, error) {

	baseProof, err := NewBaseProof(BASE_RAW_TX_SIZE)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat("base_pk.cbor"); errors.Is(err, os.ErrNotExist) {
		err = baseProof.SetupKeys()
		if err != nil {
			return nil, err
		}
		err = baseProof.WriteKeys()
		if err != nil {
			return nil, err
		}
	} else {
		err = baseProof.ReadKeys()
		if err != nil {
			return nil, err
		}
	}

	return baseProof, nil
}

func bootNormalProof(baseProof *BaseProof) (*NormalProof, error) {

	normalProof, err := NewNormalProof(baseProof.Ccs, baseProof.VerifyingKey)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat("norm_pk.cbor"); errors.Is(err, os.ErrNotExist) {
		err = normalProof.SetupKeys()
		if err != nil {
			return nil, err
		}
		err = normalProof.WriteKeys()
		if err != nil {
			return nil, err
		}
	} else {
		err = normalProof.ReadKeys()
		if err != nil {
			return nil, err
		}
	}

	return normalProof, nil
}

func BootProofSystem() {

	fmt.Println("Booting base case proof system. This will take around 1 minute")
	bp, err := bootBaseProof()
	if err != nil {
		fmt.Printf("Failed to bootstrap basecase proof system.Aborting: %s\n", err)
		return
	}
	baseProof = bp

	//bootstrap the normal case proof system
	fmt.Println("Booting normal case proof system. This will take around 1 minute")
	np, err := bootNormalProof(baseProof)
	if err != nil {
		fmt.Printf("Failed to bootstrap normalcase proof system.Aborting: %s\n", err)
		return
	}
	normalProof = np
}

/**
TX UTIL. Slicer
*/

/*
Split a Raw Transaction into it's component "prefix", "suffix" and "postfix" parts

inputIndex - the index of the input that
*/
func SliceTx(rawTx []byte, inputIndex int) ([]byte, []byte, []byte, error) {

	//tx, err := bt.NewTxFromBytes(rawTx)

	reader := bytes.NewReader(rawTx)

	txIdStart, postfixStart, err := getOffSets(uint64(inputIndex), reader)

	if err != nil {
		return nil, nil, nil, err
	}

	return rawTx[0:txIdStart], rawTx[txIdStart : txIdStart+32], rawTx[postfixStart:len(rawTx)], nil

}

func getOffSets(inputIndex uint64, r io.Reader) (int, int, error) {
	t := bt.Tx{}

	version := make([]byte, 4)
	if n, err := io.ReadFull(r, version); n != 4 || err != nil {
		return 0, 0, err
	}
	t.Version = binary.LittleEndian.Uint32(version)

	var err error

	inputCount, _, err := bt.DecodeVarIntFromReader(r)
	if err != nil {
		return 0, 0, err
	}

	if inputCount < inputIndex+1 {
		return 0, 0, fmt.Errorf("Input index is outside of the range of [%d] available inputs", inputCount)
	}

	inputCountSize := len(bt.VarInt(inputCount))

	txIdOffSet := 4 + inputCountSize //version + numInput bytes

	// create Inputs
	var i uint64 = 0
	var input *bt.Input

	//read up to input # inputIndex

	for ; i < inputIndex; i++ {
		input, err = bt.NewInputFromReader(r)
		if err != nil {
			return 0, 0, err
		}
		t.Inputs = append(t.Inputs, input)
	}

	//get the size of inputs read so far
	var inputSize int = 0
	for _, input := range t.Inputs {
		inputSize = inputSize + len(input.ToBytes(false))
	}

	//since the first entry of the next input is the txid we want
	txIdOffSet = txIdOffSet + inputSize

	postfixStart := txIdOffSet + 32

	return txIdOffSet, postfixStart, nil

}

/*
func CreateBaseCaseProof(proverOptions backend.ProverOption, innerCcs constraint.ConstraintSystem, genesisWitness witness.Witness, provingKey native_groth16.ProvingKey) (
	native_groth16.Proof,
	error,
) {
	return native_groth16.Prove(innerCcs, provingKey, genesisWitness, proverOptions)
}
*/

func CreateBaseCaseProof(pInfo *txivc.BaseProofInfo) (string, error) {

	fullTxBytes, _ := hex.DecodeString(pInfo.RawTx)

	firstHash := sha256.Sum256(fullTxBytes)
	genesisTxId := sha256.Sum256(firstHash[:])

	genesisWitness, err := txivc.CreateBaseCaseFullWitness(fullTxBytes, genesisTxId)

	if err != nil {
		return "", err
	}
	genesisProof, err := txivc.ComputeProof(baseProof.Ccs, baseProof.ProvingKey, genesisWitness)

	jsonBytes, err := json.Marshal(genesisProof)

	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}
