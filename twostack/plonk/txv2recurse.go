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
	CurrTxPrefix [5]uints.U8 //5
	PrevTxId     [32]uints.U8
	CurrTxPost   [154]uints.U8 //81

	//double-sha256 hash of the concatenation of above fields. Not reversed, so not quite a TxId
	CurrTxId [32]uints.U8 `gnark:",public"` //probably needs to provide the reversed version to save circuit space
	TokenId  [32]uints.U8 `gnark:",public"` //probably needs to provide the reversed version to save circuit space

}

/*
*
Base case implementation
*/
func (circuit *Sha256CircuitBaseCase[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {

	uapi, err := uints.New[uints.U32](api)

	//assert that currTxId == hash(prefix || prevTxId || postfix )
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

	//assert current public input matches calculated txId
	for i := range circuit.CurrTxId {
		uapi.ByteAssertEq(circuit.CurrTxId[i], calculatedTxId[i])
	}

	//assert that currTxId == TokenId
	for i := range circuit.CurrTxId {
		uapi.ByteAssertEq(circuit.TokenId[i], calculatedTxId[i])
	}

	return nil
}

/*
*
General case to continue with proofs
*/
type Sha256Circuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	PreviousProof stdplonk.Proof[FR, G1El, G2El]
	PreviousVk    stdplonk.VerifyingKey[FR, G1El, G2El] `gnark:"-"` // constant verification key

	CurrTxPrefix [5]uints.U8 //5
	PrevTxId     [32]uints.U8
	CurrTxPost   [188]uints.U8 //81

	//double-sha256 hash of the concatenation of above fields. Not reversed, so not quite a TxId
	CurrTxId [32]uints.U8 `gnark:",public"` //probably needs to provide the reversed version to save circuit space
	TokenId  [32]uints.U8 `gnark:",public"` //probably needs to provide the reversed version to save circuit space

	//placing Witness at the end so TokenId offset is more easily calculated
	PreviousWitness stdplonk.Witness[FR] `gnark:",public"`
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

	//Set PrevTxId to null for genesis, and assert that current TxId is TokenId
	//uapi, err := uints.New[uints.U32](api)
	//if isNullArray(circuit.PrevTxId[:]) || (circuit.PreviousWitness.Public == nil) {
	//
	//	//it's genesis. We must enforce equality of tokenid and current txid
	//	for i := range circuit.TokenId {
	//		uapi.ByteAssertEq(circuit.TokenId[i], circuit.CurrTxId[i])
	//	}
	//
	//	return nil
	//}

	//assert that the token ID is being preserved
	uapi, err := uints.New[uints.U32](api)
	//field, err := emulated.NewField[FR](api)
	//tokenOffset := 32 //FIXME: Figure out the proper tokenId offset in public variables
	//for i := range circuit.TokenId {
	//	witnessTokenIdBits := field.ToBits(&circuit.PreviousWitness.Public[i+tokenOffset])
	//	witnessTokenId := bits.FromBinary(api, witnessTokenIdBits)
	//	uapi.ByteAssertEq(circuit.TokenId[i], uapi.ByteValueOf(witnessTokenId))
	//}

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

	//  construct a verifier in-circuit
	verifier, err := stdplonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}

	//verify the previous proof
	err = verifier.AssertProof(circuit.PreviousVk, circuit.PreviousProof, circuit.PreviousWitness, stdplonk.WithCompleteArithmetic())

	if err != nil {
		return err
	}

	return nil
}
