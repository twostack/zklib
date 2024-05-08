package txivc

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	stdplonk "github.com/consensys/gnark/std/recursion/plonk"
)

/*
*
Base case to generate initial proof to get things started
*/
type Sha256CircuitBaseCase[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	//CurrTxPrefix [5]uints.U8 //5
	//PrevTxId     [32]uints.U8
	//CurrTxPost   [154]uints.U8 //81
	RawTx []uints.U8 `gnark:",public"`

	//double-sha256 hash of the concatenation of above fields. Not reversed, so not quite a TxId
	CurrTxId [32]uints.U8 `gnark:",public"` //probably needs to provide the reversed version to save circuit space

}

/*
*
Base case implementation
*/
func (circuit *Sha256CircuitBaseCase[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {

	uapi, err := uints.New[uints.U32](api)

	//do double-sha256
	firstHash, err := calculateSha256(api, circuit.RawTx)
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
*
General case to continue with proofs
*/
type Sha256Circuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	PreviousProof   stdplonk.Proof[FR, G1El, G2El]
	PreviousVk      stdplonk.VerifyingKey[FR, G1El, G2El] `gnark:"-"` // constant verification key
	PreviousWitness stdplonk.Witness[FR]

	CurrTxPrefix [5]uints.U8 //5
	PrevTxId     [32]uints.U8
	CurrTxPost   [188]uints.U8 //81

	//double-sha256 hash of the concatenation of above fields. Not reversed, so not quite a TxId
	//TokenId  [32]uints.U8 `gnark:",public"` //probably needs to provide the reversed version to save circuit space
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

	//assert that the token ID is being preserved
	uapi, err := uints.New[uints.U32](api)
	//field, err := emulated.NewField[FR](api)
	//
	////fmt.Printf("Checking previous txnid against witness")
	//for i := range circuit.CurrTxId {
	//	//assert that the previous txn id (in witness) matches that of the current outpoint (in prevTxnId)
	//	witnessTxIdBits := field.ToBits(&circuit.PreviousWitness.Public[i])
	//	witnessTxIdByte := bits.FromBinary(api, witnessTxIdBits)
	//	uapi.ByteAssertEq(circuit.PrevTxId[i], uapi.ByteValueOf(witnessTxIdByte))
	//}
	//fmt.Printf("PrevTxnId checks out")

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
	//fmt.Printf("Checking claimed digest matches\n")
	for i := range circuit.CurrTxId {
		uapi.ByteAssertEq(circuit.CurrTxId[i], calculatedTxId[i])
	}
	//fmt.Printf("Claimed digest matches OK\n")

	//  construct a verifier in-circuit
	verifier, err := stdplonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}

	//fmt.Printf("Verifying previous proof\n")
	//verify the previous proof
	err = verifier.AssertProof(circuit.PreviousVk, circuit.PreviousProof, circuit.PreviousWitness, stdplonk.WithCompleteArithmetic())
	//fmt.Printf("Proof checks out\n")

	if err != nil {
		return err
	}

	return nil
}
