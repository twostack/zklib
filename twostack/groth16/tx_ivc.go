package txivc

import (
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
type Sha256CircuitBaseCase[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	RawTx []frontend.Variable

	//double-sha256 hash of the concatenation of above fields. Not reversed, so not quite a TxId
	CurrTxId [32]uints.U8 `gnark:",public"` //probably needs to provide the reversed version to save circuit space
}

/*
* Base case implementation
 */
func (circuit *Sha256CircuitBaseCase[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {

	uapi, err := uints.New[uints.U32](api)

	ret := make([]uints.U8, len(circuit.RawTx))
	for i := range ret {
		ret[i] = uapi.ByteValueOf(circuit.RawTx[i])
	}

	//do double-sha256
	firstHash, err := calculateSha256(api, ret)
	if err != nil {
		return err
	}
	calculatedTxId, err := calculateSha256(api, firstHash)
	if err != nil {
		return err
	}

	//assert current public input matches calculated txId
	for i := range circuit.CurrTxId {
		uapi.ByteAssertEq(circuit.CurrTxId[i], calculatedTxId[i])
	}

	return nil
}

/*
* General case to continue with proofs
 */
type Sha256Circuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	PreviousProof   stdgroth16.Proof[G1El, G2El]
	PreviousVk      stdgroth16.VerifyingKey[G1El, G2El, GtEl] `gnark:"-"` // constant verification key
	PreviousWitness stdgroth16.Witness[FR]

	CurrTxPrefix [5]uints.U8 //5
	PrevTxId     [32]uints.U8
	CurrTxPost   [188]uints.U8 //81

	//double-sha256 hash of the concatenation of above fields. Not reversed, so not quite a TxId
	CurrTxId [32]uints.U8 `gnark:",public"` //probably needs to provide the reversed version to save circuit space
}

func isNullArray(arr []uints.U8) bool {
	zeroVal := uints.NewU8(0)
	for i := range arr {
		if arr[i] != zeroVal {
			return false
		}
	}

	return true
}

func (circuit *Sha256Circuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {

	uapi, err := uints.New[uints.U32](api)

	field, err := emulated.NewField[FR](api)
	for i := range circuit.CurrTxId {
		//assert that the previous txn id (in witness) matches that of the current outpoint (in prevTxnId)
		witnessTxIdBits := field.ToBits(&circuit.PreviousWitness.Public[i])
		witnessTxId := bits.FromBinary(api, witnessTxIdBits)
		uapi.ByteAssertEq(circuit.PrevTxId[i], uapi.ByteValueOf(witnessTxId))
	}

	//reconstitute the transaction hex
	fullTx := append(circuit.CurrTxPrefix[:], circuit.PrevTxId[:]...)
	fullTx = append(fullTx, circuit.CurrTxPost[:]...)

	//do double-sha256
	firstHash, err := calculateSha256(api, fullTx)
	if err != nil {
		return err
	}
	calculatedTxId, err := calculateSha256(api, firstHash)
	if err != nil {
		return err
	}

	//loop over the individual bytes of the calculated hash
	//and compare them to the expected digest
	for i := range circuit.CurrTxId {
		uapi.ByteAssertEq(circuit.CurrTxId[i], calculatedTxId[i])
	}

	verifier, err := stdgroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	verifier.AssertProof(circuit.PreviousVk, circuit.PreviousProof, circuit.PreviousWitness)

	if err != nil {
		return err
	}

	return nil
}
