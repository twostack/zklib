package txivc

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

/*
* Base case to generate initial proof to get things started
 */
type Sha256CircuitBaseCase struct {
	RawTx []frontend.Variable

	//double-sha256 hash of the concatenation of above fields. Not reversed, so not quite a TxId
	CurrTxId []frontend.Variable `gnark:",public"` //probably needs to provide the reversed version to save circuit space
}

/*
* Base case implementation
 */
func (circuit *Sha256CircuitBaseCase) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)

	//assign the pre-image for in-circuit sha256d() calculation
	rawTxArr := make([]uints.U8, len(circuit.RawTx))
	for ndx := range circuit.RawTx {
		rawTxArr[ndx] = uapi.ByteValueOf(circuit.RawTx[ndx])
	}

	//do double-sha256
	firstHash, err := calculateSha256(api, rawTxArr)
	if err != nil {
		return err
	}
	calculatedTxId, err := calculateSha256(api, firstHash)
	if err != nil {
		return err
	}

	//assert current public input matches calculated txId
	for i := range circuit.CurrTxId {
		uapi.ByteAssertEq(uapi.ByteValueOf(circuit.CurrTxId[i]), calculatedTxId[i])
	}

	return nil
}

/*
* General case to continue with proofs
 */
type Sha256Circuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	PreviousProof   stdgroth16.Proof[G1El, G2El]
	PreviousVk      stdgroth16.VerifyingKey[G1El, G2El, GtEl]
	PreviousWitness stdgroth16.Witness[FR]

	CurrTxPrefix []frontend.Variable
	PrevTxId     []frontend.Variable
	CurrTxPost   []frontend.Variable

	//double-sha256 hash of the concatenation of above fields. Not reversed, so not quite a TxId
	CurrTxId []frontend.Variable `gnark:",public"` //probably needs to provide the reversed version to save circuit space
}

func (circuit *Sha256Circuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {

	verifier, err := stdgroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return err
	}

	err = verifier.AssertProof(circuit.PreviousVk, circuit.PreviousProof, circuit.PreviousWitness, stdgroth16.WithCompleteArithmetic())
	if err != nil {
		return err
	}

	uapi, err := uints.New[uints.U32](api)
	field, err := emulated.NewField[FR](api)

	for i := range circuit.CurrTxId {
		//assert that the previous txn id (in witness) matches that of the current outpoint (in prevTxnId)
		witnessTxIdBits := field.ToBits(&circuit.PreviousWitness.Public[i])
		witnessTxIdByte := bits.FromBinary(api, witnessTxIdBits)
		uapi.ByteAssertEq(uapi.ByteValueOf(circuit.PrevTxId[i]), uapi.ByteValueOf(witnessTxIdByte))
	}

	//reconstitute the transaction hex
	fullTx := append(circuit.CurrTxPrefix[:], circuit.PrevTxId[:]...)
	fullTx = append(fullTx, circuit.CurrTxPost[:]...)

	rawTxArr := make([]uints.U8, len(fullTx))
	for ndx := range fullTx {
		rawTxArr[ndx] = uapi.ByteValueOf(fullTx[ndx])
	}

	//do double-sha256
	firstHash, err := calculateSha256(api, rawTxArr)
	if err != nil {
		return fmt.Errorf("Failed to calculate first round sha256")
	}
	calculatedTxId, err := calculateSha256(api, firstHash)
	if err != nil {
		return fmt.Errorf("Failed to calculate second round sha256")
	}

	//loop over the individual bytes of the calculated hash
	//and compare them to the expected digest, asserting
	//that the claimed CurrTxId matches that of the provided rawtx
	for i := range circuit.CurrTxId {
		uapi.ByteAssertEq(uapi.ByteValueOf(circuit.CurrTxId[i]), calculatedTxId[i])
	}

	return nil

}
