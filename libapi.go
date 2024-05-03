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
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/libsv/go-bt"
	txivc "github.com/twostack/zklib/twostack/groth16"
	"io"
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

type ProofSystem struct {
	InnerField *big.Int
	OuterField *big.Int

	verifierOptions backend.VerifierOption
	proverOptions   backend.ProverOption

	//normal params
	normalCurveId      ecc.ID
	normalCcs          *constraint.ConstraintSystem
	normalVerifyingKey *native_groth16.VerifyingKey
	normalProvingKey   *native_groth16.ProvingKey

	///
	baseCurveId      ecc.ID
	baseCcs          *constraint.ConstraintSystem
	baseVerifyingKey *native_groth16.VerifyingKey
	baseProvingKey   *native_groth16.ProvingKey
}

func NewProofSystem() (*ProofSystem, error) {

	ps := &ProofSystem{}

	ps.InnerField = txivc.InnerCurve.ScalarField()
	ps.OuterField = txivc.OuterCurve.ScalarField()

	err := ps.setupBaseCase(BASE_RAW_TX_SIZE)

	if err != nil {
		return nil, err
	}

	err = ps.setupNormalCase()

	if err != nil {
		return nil, err
	}

	return ps, nil
}

func (ps *ProofSystem) setupNormalCase() error {

	//IMPORTANT: Normal proof needs to read the OUTER field's curveId
	ps.normalCurveId = txivc.OuterCurve

	normalCcs, provingKey, verifyingKey, err := ps.readNormalSetupParams(ps.OuterField)

	if err != nil {
		return err
	}

	ps.normalCcs = &normalCcs
	ps.normalProvingKey = &provingKey
	ps.normalVerifyingKey = &verifyingKey

	return nil
}

func (ps *ProofSystem) readNormalSetupParams(outerField *big.Int) (constraint.ConstraintSystem, native_groth16.ProvingKey, native_groth16.VerifyingKey, error) {

	if _, err := os.Stat("norm_ccs.cbor"); errors.Is(err, os.ErrNotExist) {

		//setup normal case for base parent VK
		normalCcs, provingKey, verifyingKey, err := txivc.SetupNormalCase(outerField, *ps.baseCcs, *ps.baseVerifyingKey)

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
		normalCcs, err := ps.readCircuitParams("norm_")
		if err != nil {
			return nil, nil, nil, err
		}

		verifyingKey, provingKey, err := readKeys("norm_", ps.normalCurveId)
		if err != nil {
			return nil, nil, nil, err
		}

		return normalCcs, provingKey, verifyingKey, nil
	}
}

func (ps *ProofSystem) setupBaseCase(baseTxSize int) error {

	//IMPORTANT: Base proof needs to read the inner field's curveId
	ps.baseCurveId = txivc.InnerCurve

	ps.verifierOptions = groth16.GetNativeVerifierOptions(ps.OuterField, ps.InnerField)
	ps.proverOptions = groth16.GetNativeProverOptions(ps.OuterField, ps.InnerField)

	baseCcs, baseProvingKey, baseVerifyingKey, err := ps.readBaseParams(baseTxSize, ps.InnerField)

	//ccs, err := frontend.Compile(po.InnerField, r1cs.NewBuilder, baseTxCircuit)
	if err != nil {
		return err
	}

	ps.baseCcs = &baseCcs
	ps.baseProvingKey = &baseProvingKey
	ps.baseVerifyingKey = &baseVerifyingKey

	return nil
}

func (ps *ProofSystem) readBaseParams(txSize int, innerField *big.Int) (constraint.ConstraintSystem, native_groth16.ProvingKey, native_groth16.VerifyingKey, error) {

	if _, err := os.Stat("base_ccs.cbor"); errors.Is(err, os.ErrNotExist) {

		baseCcs, provingKey, verifyingKey, err := txivc.SetupBaseCase(txSize, innerField)

		baseccsFile, err := os.Create("base_ccs.cbor")
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
		baseCcs, err := ps.readCircuitParams("base_")
		if err != nil {
			return nil, nil, nil, err
		}

		verifyingKey, provingKey, err := readKeys("base_", ps.baseCurveId)
		if err != nil {
			return nil, nil, nil, err
		}

		return baseCcs, provingKey, verifyingKey, nil
	}
}

func (ps *ProofSystem) readCircuitParams(prefix string) (constraint.ConstraintSystem, error) {

	baseCcs := native_groth16.NewCS(txivc.InnerCurve)

	ccsFile, err := os.OpenFile(prefix+"ccs.cbor", os.O_RDONLY, 0444) //read-only
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

func (ps *ProofSystem) CreateNormalCaseProof(normalInfo *txivc.NormalProofInfo) (string, error) {
	//outerAssignment := normalProof.CreateOuterAssignment()

	var prevTxCcs constraint.ConstraintSystem
	var prevTxVk native_groth16.VerifyingKey

	var prevTxWitness *witness.Witness
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
		prevTxCcs = *ps.baseCcs
		prevTxVk = *ps.baseVerifyingKey
		prevTxProof = native_groth16.NewProof(ps.baseCurveId)
		prevTxWitness, err = txivc.CreateBaseCaseLightWitness(currTxId[:], ps.InnerField)
		if err != nil {
			return "", err
		}

	} else {
		/*
			prevTxCcs = *ps.normalCcs
			prevTxVk = *ps.normalVerifyingKey
			prevTxProof = native_groth16.NewProof(normalProof.CurveId)
			prevTxWitness, err = txivc.CreateNormalLightWitness(currTxId[:], normalProof.InnerField)
			if err != nil {
				return "", err
			}
		*/
		return "proof with non-base case txn is not implemented yet", nil
	}

	var innerProofBytes = []byte(normalInfo.Proof)
	err = json.Unmarshal(innerProofBytes, &prevTxProof)
	if err != nil {
		//log.Error().Msg(fmt.Sprintf("Error unmarshalling proof : [%s]\n", err.Error()))
		return "", err
	}

	normalWitness, err := txivc.CreateNormalFullWitness(
		*prevTxWitness,
		prevTxProof,
		prevTxVk,
		prefixBytes,
		prevTxnId,
		postfixBytes,
		fullTxBytes,
		ps.OuterField,
	)
	if err != nil {
		return "", err
	}

	resultProof, err := txivc.ComputeProof(&prevTxCcs, ps.normalProvingKey, normalWitness)
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

func (ps *ProofSystem) CreateBaseCaseProof(pInfo *txivc.BaseProofInfo) (string, error) {

	fullTxBytes, _ := hex.DecodeString(pInfo.RawTx)

	firstHash := sha256.Sum256(fullTxBytes)
	genesisTxId := sha256.Sum256(firstHash[:])

	genesisWitness, err := txivc.CreateBaseCaseFullWitness(fullTxBytes, genesisTxId)

	if err != nil {
		return "", err
	}
	genesisProof, err := txivc.ComputeProof(ps.baseCcs, ps.baseProvingKey, genesisWitness)

	jsonBytes, err := json.Marshal(genesisProof)

	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}

func (ps *ProofSystem) VerifyBaseProof(txId string, jsonProof string) bool {

	txProof := native_groth16.NewProof(txivc.InnerCurve)

	err := json.Unmarshal([]byte(jsonProof), &txProof)
	if err != nil {
		fmt.Printf("%s", err)
		return false
	}

	genesisTxId, err := hex.DecodeString(txId)
	if err != nil {
		fmt.Printf("%s", err)
		return false
	}
	publicWitness, err := txivc.CreateBaseCaseLightWitness(genesisTxId[:], ps.InnerField)
	if err != nil {
		fmt.Printf("%s", err)
		return false
	}

	//isVerified := ps.VerifyProof(publicWitness, &txProof)

	//func (po *BaseProof) VerifyProof(witness *witness.Witness, proof *native_groth16.Proof) bool {
	err = native_groth16.Verify(txProof, *ps.baseVerifyingKey, *publicWitness, ps.verifierOptions)
	if err != nil {
		fmt.Printf("Fail on proof verification! %s\n", err)
		return false
	}

	return true

}

var BASE_RAW_TX_SIZE = 191

func BootBaseProof(baseTxSize int) (*BaseProof, error) {

	baseProof, err := NewBaseProof(baseTxSize)
	if err != nil {
		return nil, err
	}

	return baseProof, nil
}

func bootNormalProof(baseProof *BaseProof) (*NormalProof, error) {

	normalProof, err := NewNormalProof(baseProof)
	if err != nil {
		return nil, err
	}

	return normalProof, nil
}

//func BootProofSystem() (*BaseProof, *NormalProof, error) {
//
//	fmt.Println("Booting base case proof system. This will take around 1 minute")
//	bp, err := BootBaseProof(BASE_RAW_TX_SIZE)
//	if err != nil {
//		fmt.Printf("Failed to bootstrap basecase proof system.Aborting: %s\n", err)
//		return nil, nil, err
//	}
//
//	//bootstrap the normal case proof system
//	fmt.Println("Booting normal case proof system. This will take around 1 minute")
//	np, err := bootNormalProof(bp)
//	if err != nil {
//		fmt.Printf("Failed to bootstrap normalcase proof system.Aborting: %s\n", err)
//		return nil, nil, err
//	}
//
//	return bp, np, nil
//}

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
