package txivc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	native_groth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/libsv/go-bt"
	"io"
	"math/big"
)

type BaseProofInfo struct {
	RawTx string `json:"raw_tx" binding:"required"`
}
type NormalProofInfo struct {
	RawTx        string `json:"raw_tx" binding:"required"`
	InputIndex   int    `json:"input_index"`
	IsParentBase bool   `json:"is_parent_base"`
	Proof        string `json:"proof" binding:"required"`
}

var InnerCurve = ecc.BLS12_377
var OuterCurve = ecc.BW6_761

type ScalarField = sw_bls12377.ScalarField
type G1Affine = sw_bls12377.G1Affine
type G2Affine = sw_bls12377.G2Affine
type GTEl = sw_bls12377.GT

//var InnerCurve = ecc.BLS24_315
//var OuterCurve = ecc.BW6_633

//type ScalarField = sw_bls24315.ScalarField
//type G1Affine = sw_bls24315.G1Affine
//type G2Affine = sw_bls24315.G2Affine
//type GTEl = sw_bls24315.GT

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

func SetupBaseCase(txSize int, innerField *big.Int) (constraint.ConstraintSystem, native_groth16.ProvingKey, native_groth16.VerifyingKey, error) {

	baseCcs, err := frontend.Compile(innerField, r1cs.NewBuilder,
		&Sha256CircuitBaseCase{
			RawTx:    make([]frontend.Variable, txSize),
			CurrTxId: make([]frontend.Variable, 32), //32 bytes for the txId
		})

	if err != nil {
		return nil, nil, nil, err
	}

	innerPK, innerVK, err := native_groth16.Setup(baseCcs)
	if err != nil {
		return nil, nil, nil, err
	}
	return baseCcs, innerPK, innerVK, nil
}

func SetupNormalCase(prefixSize int, postfixSize int, outerField *big.Int, parentCcs constraint.ConstraintSystem) (constraint.ConstraintSystem, native_groth16.ProvingKey, native_groth16.VerifyingKey, error) {

	outerCcs, err := frontend.Compile(outerField, r1cs.NewBuilder,
		&Sha256Circuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
			PreviousProof:   groth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](parentCcs),
			PreviousVk:      groth16.PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](parentCcs),
			PreviousWitness: groth16.PlaceholderWitness[sw_bls12377.ScalarField](parentCcs),

			CurrTxPrefix: make([]frontend.Variable, prefixSize),
			CurrTxPost:   make([]frontend.Variable, postfixSize),
			PrevTxId:     make([]frontend.Variable, 32),
			CurrTxId:     make([]frontend.Variable, 32),
		})

	if err != nil {
		fmt.Printf("Error compile normal circuit : %s", err)
		return nil, nil, nil, err
	}

	outerPk, outerVk, err := native_groth16.Setup(outerCcs)
	if err != nil {
		fmt.Printf("Error during setup of normal circuit : %s", err)
		return nil, nil, nil, err
	}
	return outerCcs, outerPk, outerVk, nil
}

func CreateBaseCaseLightWitness(
	currTxId []byte,
	innerField *big.Int,
) (witness.Witness, error) {

	innerAssignment := Sha256CircuitBaseCase{
		CurrTxId: make([]frontend.Variable, 32),
	}

	for ndx, entry := range currTxId {
		innerAssignment.CurrTxId[ndx] = entry
	}

	innerWitness, err := frontend.NewWitness(&innerAssignment, innerField, frontend.PublicOnly())
	if err != nil {
		return nil, err
	}
	return innerWitness, nil
}

func CreateBaseCaseFullWitness(
	rawTxBytes []byte,
	currTxId []byte,
) (witness.Witness, error) {

	innerAssignment := Sha256CircuitBaseCase{
		RawTx:    make([]frontend.Variable, len(rawTxBytes)),
		CurrTxId: make([]frontend.Variable, len(currTxId)),
	}

	//assign the current Txn data
	for ndx := range rawTxBytes {
		innerAssignment.RawTx[ndx] = rawTxBytes[ndx]
	}
	for ndx := range currTxId {
		innerAssignment.CurrTxId[ndx] = currTxId[ndx]
	}

	innerWitness, err := frontend.NewWitness(&innerAssignment, ecc.BLS12_377.ScalarField())
	if err != nil {
		return nil, err
	}
	return innerWitness, nil
}

/*
*
Full witness is used for generating a new proof
*/
func CreateNormalFullWitness(
	innerWitness witness.Witness,
	innerProof native_groth16.Proof,
	innerVk native_groth16.VerifyingKey,
	prefixBytes []byte, prevTxnIdBytes []byte, postFixBytes []byte, currTxId []byte, field *big.Int) (witness.Witness, error) {

	circuitVk, err := groth16.ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVk)
	circuitWitness, err := groth16.ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	circuitProof, err := groth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)

	outerAssignment := CreateOuterAssignment(circuitWitness, circuitProof, circuitVk, prefixBytes, prevTxnIdBytes, postFixBytes, currTxId)
	fullWitness, err := frontend.NewWitness(&outerAssignment, field)

	if err != nil {
		return nil, err
	}

	return fullWitness, nil
}

/*
*
Light witness is used for verification of an existing proof. I.e. only public params are filled.
*/
func CreateNormalLightWitness(txId []byte, outerField *big.Int) (witness.Witness, error) {

	outerAssignment := Sha256Circuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		CurrTxId: make([]frontend.Variable, 32),
	}

	for ndx := range txId {
		outerAssignment.CurrTxId[ndx] = txId[ndx]
	}

	lightWitness, err := frontend.NewWitness(&outerAssignment, outerField, frontend.PublicOnly())
	if err != nil {
		return nil, err
	}

	return lightWitness, nil

}

func CreateOuterAssignment(
	circuitWitness groth16.Witness[sw_bls12377.ScalarField],
	circuitProof groth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine],
	verifyingKey groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT],
	prefixBytes []byte, prevTxnIdBytes []byte, postFixBytes []byte, currTxId []byte) Sha256Circuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT] {

	outerAssignment := Sha256Circuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		PreviousWitness: circuitWitness,
		PreviousProof:   circuitProof,
		PreviousVk:      verifyingKey,

		CurrTxPrefix: make([]frontend.Variable, len(prefixBytes)),
		CurrTxPost:   make([]frontend.Variable, len(postFixBytes)),
		PrevTxId:     make([]frontend.Variable, len(prevTxnIdBytes)),
		CurrTxId:     make([]frontend.Variable, len(currTxId)),
	}

	for ndx := range prefixBytes {
		outerAssignment.CurrTxPrefix[ndx] = prefixBytes[ndx]
	}
	for ndx := range postFixBytes {
		outerAssignment.CurrTxPost[ndx] = postFixBytes[ndx]
	}
	for ndx := range prevTxnIdBytes {
		outerAssignment.PrevTxId[ndx] = prevTxnIdBytes[ndx]
	}
	for ndx := range currTxId {
		outerAssignment.CurrTxId[ndx] = currTxId[ndx]
	}

	return outerAssignment
}

func VerifyProof(pubWitness witness.Witness, genesisProof native_groth16.Proof, verifyingKey native_groth16.VerifyingKey) bool {
	verifierOptions := groth16.GetNativeVerifierOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
	err := native_groth16.Verify(genesisProof, verifyingKey, pubWitness, verifierOptions)
	if err != nil {
		fmt.Printf("Fail on base case verification! %s\n", err)
		return false
	}
	return true
}

func ComputeProof(ccs constraint.ConstraintSystem, provingKey native_groth16.ProvingKey, outerWitness witness.Witness) (native_groth16.Proof, error) {

	proverOptions := groth16.GetNativeProverOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
	return native_groth16.Prove(ccs, provingKey, outerWitness, proverOptions)
}

/*
func CreateNormalCaseProof(
	baseCcs constraint.ConstraintSystem,
	baseVk native_groth16.VerifyingKey,
	baseCurveId ecc.ID,
	innerField *big.Int,
	outerField *big.Int,
	normalProvingKey native_groth16.ProvingKey,
	normalInfo *NormalProofInfo) (string, error) {

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
		prevTxCcs = baseCcs
		prevTxVk = baseVk
		prevTxProof = native_groth16.NewProof(baseCurveId)
		prevTxWitness, err = CreateBaseCaseLightWitness(currTxId[:], innerField)
		if err != nil {
			return "", err
		}

	} else {
			//prevTxCcs = *ps.normalCcs
			//prevTxVk = *ps.normalVerifyingKey
			//prevTxProof = native_groth16.NewProof(normalProof.CurveId)
			//prevTxWitness, err = txivc.CreateNormalLightWitness(currTxId[:], normalProof.InnerField)
			//if err != nil {
			//	return "", err
			//}
		return "proof with non-base case txn is not implemented yet", nil
	}

	var innerProofBytes = []byte(normalInfo.Proof)
	err = json.Unmarshal(innerProofBytes, &prevTxProof)
	if err != nil {
		//log.Error().Msg(fmt.Sprintf("Error unmarshalling proof : [%s]\n", err.Error()))
		return "", err
	}

	normalWitness, err := CreateNormalFullWitness(
		prevTxWitness,
		prevTxProof,
		prevTxVk,
		prefixBytes,
		prevTxnId,
		postfixBytes,
		currTxId[:],
		outerField,
	)
	if err != nil {
		return "", err
	}

	resultProof, err := ComputeProof(prevTxCcs, normalProvingKey, normalWitness)
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

func UnmarshalProof(proof string, curveId ecc.ID) (native_groth16.Proof, error) {

	proofObj := native_groth16.NewProof(curveId)

	err := json.Unmarshal([]byte(proof), &proofObj)
	if err != nil {
		fmt.Printf("Error unmarshalling proof : [%s]\n", err.Error())
		return nil, err
	}

	return proofObj, nil
}
