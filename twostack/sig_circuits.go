package twostack

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	stdplonk "github.com/consensys/gnark/std/recursion/plonk"
)

type SigCircuitBaseCase[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	//private params
	TxPreImage []uints.U8
	PrivateKey [64]uints.U8

	//public params
	//double-sha256 hash of the concatenation of above fields. Not reversed, so not quite a TxId
	CurrTxId  [32]uints.U8 `gnark:",public"`
	TokenId   [32]uints.U8 `gnark:",public"` //probably needs to provide the reversed version to save circuit space
	Signature [72]uints.U8 `gnark:",public"`
	PublicKey [64]uints.U8 `gnark:",public"`
}

func (circuit *SigCircuitBaseCase[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {

	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	//parse TxPreImage to obtain PrevTxId

	//create ECDSA Signature that pins committed CurrTxId
	//to the issuance Txn's prevTxId(outpoint)
	//Sig(PrevTxId||CurrTxId)

	//verify Signature commitment
	//public Signature  == in-circuit Signature

	//for i := range circuit.CurrTxId {
	//	uapi.ByteAssertEq(circuit.CurrTxId[i], calculatedTxId[i])
	//}

	//assert that currTxId == TokenId
	for i := range circuit.CurrTxId {
		uapi.ByteAssertEq(circuit.TokenId[i], circuit.CurrTxId[i])
	}

	return nil
}

type SigCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	PreviousProof stdplonk.Proof[FR, G1El, G2El]
	PreviousVk    stdplonk.VerifyingKey[FR, G1El, G2El] `gnark:"-"` // constant verification key

	//private params
	TxPreImage []uints.U8
	PrivateKey [64]uints.U8

	//public params
	//double-sha256 hash of the concatenation of above fields. Not reversed, so not quite a TxId
	CurrTxId        [32]uints.U8         `gnark:",public"`
	TokenId         [32]uints.U8         `gnark:",public"` //probably needs to provide the reversed version to save circuit space
	Signature       [72]uints.U8         `gnark:",public"`
	PublicKey       [64]uints.U8         `gnark:",public"`
	PreviousWitness stdplonk.Witness[FR] `gnark:",public"`
}

func (circuit *SigCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {

	//assert that TokenId == Witness.tokenId
	//field, err := emulated.NewField[FR](api)
	//tokenOffset := 32 //FIXME: Figure out the proper tokenId offset in public variables
	//for i := range circuit.TokenId {
	//	witnessTokenIdBits := field.ToBits(&circuit.PreviousWitness.Public[i+tokenOffset])
	//	witnessTokenId := bits.FromBinary(api, witnessTokenIdBits)
	//	uapi.ByteAssertEq(circuit.TokenId[i], uapi.ByteValueOf(witnessTokenId))
	//}

	//parse TxPreImage to obtain
	//1. PrevTxId
	//2. Signature from Input
	//3. Public Key from Input

	return nil
}
