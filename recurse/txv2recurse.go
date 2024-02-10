package recurse

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	stdplonk "github.com/consensys/gnark/std/recursion/plonk"
)

type Sha256Circuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        stdplonk.Proof[FR, G1El, G2El]
	VerifyingKey stdplonk.VerifyingKey[FR, G1El, G2El] `gnark:"-"` // constant verification key
	InnerWitness stdplonk.Witness[FR]                  `gnark:",public"`

	CurrTxPrefix [5]uints.U8 //5
	PrevTxId     [32]uints.U8
	CurrTxPost   [154]uints.U8 //81

	//double-sha256 hash of the concatenation of above fields. Not reversed, so not quite a TxId
	CurrTxId [32]uints.U8 `gnark:",public"` //probably needs to provide the reversed version to save circuit space
	TokenId  [32]uints.U8 `gnark:",public"` //probably needs to provide the reversed version to save circuit space
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
	if isNullArray(circuit.PrevTxId[:]) {
		api.AssertIsEqual(circuit.TokenId, circuit.CurrTxId)
	}

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
	uapi, err := uints.New[uints.U32](api)
	for i := range circuit.CurrTxId {
		uapi.ByteAssertEq(circuit.CurrTxId[i], calculatedTxId[i])
	}

	/**
	Following section of code is copied from the nonnative_doc_test.go example
	*/
	verifier, err := stdplonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}

	/*
	  It would be sufficient to assert that the value of
	  circuit.InnerWitness.Public must == circuit.PrevTxId
	*/

	err = verifier.AssertProof(circuit.VerifyingKey, circuit.Proof, circuit.InnerWitness, stdplonk.WithCompleteArithmetic())

	if err != nil {
		return err
	}

	return nil
	/*
		field, err := emulated.NewField[FR](api)
		uapi, err := uints.New[uints.U32](api)
		for i := range circuit.PrevTxId {
			innerBits := field.ToBits(&circuit.InnerWitness.Public[i])
			innerVal := bits.FromBinary(api, innerBits)
			uapi.ByteAssertEq(circuit.PrevTxId[i], uapi.ByteValueOf(innerVal))
			//api.AssertIsEqual(circuit.PrevTxId[i].Val, innerVal)
		}
	*/
}
