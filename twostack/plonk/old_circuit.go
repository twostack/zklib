package txivc

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

// circuit that proves in zero knowledge that there exists
// a Transaction with Id == CurrTxId which is composed of
// sha256(sha256(CurrTxPrefix || PrevTxId || CurrTxPost))
type Sha256InnerCircuit struct {
	CurrTxPrefix [5]uints.U8 //5
	PrevTxId     [32]uints.U8
	CurrTxPost   [154]uints.U8 //81

	//double-sha256 hash of the concatenation of above fields. Not reversed, so not quite a TxId
	CurrTxId [32]uints.U8 `gnark:",public"` //probably needs to provide the reversed version to save circuit space
}

func (circuit *Sha256InnerCircuit) Define(api frontend.API) error {

	fullTx := append(circuit.CurrTxPrefix[:], circuit.PrevTxId[:]...)
	fullTx = append(fullTx, circuit.CurrTxPost[:]...)

	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	//do double-sha256
	firstHash, err2 := calculateSha256(api, fullTx)
	if err2 != nil {
		return err2
	}
	calculatedTxId, err2 := calculateSha256(api, firstHash)
	if err2 != nil {
		return err2
	}

	//loop over the individual bytes of the calculated hash
	//and compare them to the expected digest
	for i := range circuit.CurrTxId {
		uapi.ByteAssertEq(circuit.CurrTxId[i], calculatedTxId[i])
	}

	return nil
}

func calculateSha256(api frontend.API, preImage []uints.U8) ([]uints.U8, error) {
	//instantiate a sha256 circuit
	sha256, err := sha2.New(api)

	if err != nil {
		return nil, err
	}

	//write the preimage into the circuit
	sha256.Write(preImage)

	//use the circuit directly to calculate the double-sha256 hash
	res := sha256.Sum()

	//assert that the circuit calculated correct hash length . Maybe not needed.
	if len(res) != 32 {
		return nil, fmt.Errorf("not 32 bytes")
	}
	return res, nil
}

/*
type Sha256OuterCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        stdplonk.Proof[FR, G1El, G2El]
	VerifyingKey stdplonk.VerifyingKey[FR, G1El, G2El] `gnark:"-"` // constant verification key
	InnerWitness stdplonk.Witness[FR]                  `gnark:",public"`

	 //the prevtxid of the outer circuit must be matched and equal to the currtxid of the innerproof.
	 //  because the innerproof that we are verifying for the current transaction
	 //  was actually generated in/for the parent transaction (in who's context it was the )
	 //
	 //  furthermore, both of the following must be public, because the verifying wallet
	 //  will need to look at current txn, extract these public values.
	 //  And use them to validate the provided Outer PreviousProof.
	PrevTxId [32]uints.U8 `gnark:",public"`
}

*/

/*
*

	The outer circuit for our recursive proof that accumulates a chain of transactions.
*/
/**
func (circuit *Sha256OuterCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {

	//Following section of code is copied from the nonnative_doc_test.go example
	verifier, err := stdplonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}

	  //It would be sufficient to assert that the value of
	  //circuit.PreviousWitness.Public must == circuit.PrevTxId
	  //
	err = verifier.AssertProof(circuit.VerifyingKey, circuit.Proof, circuit.InnerWitness, stdplonk.WithCompleteArithmetic())

	if err != nil {
		return err
	}

	//NOTE: Check whether we might need to also mess with the CurrentTxId somehow in the outer proof
	//      I don't think we need to try and explicitly pass that info though. It should be implicitly
	//      carried as public part of Witness in Outer Circuit's PreviousProof (yes ? )

		//The following might be sufficient for the recursive case, since the
		//public input (PrevTxId) is provided as part of the Witness of the Outer Circuit along with PrevProof

	field, err := emulated.NewField[FR](api)
	uapi, err := uints.New[uints.U32](api)
	for i := range circuit.PrevTxId {
		innerBits := field.ToBits(&circuit.InnerWitness.Public[i])
		innerVal := bits.FromBinary(api, innerBits)
		uapi.ByteAssertEq(circuit.PrevTxId[i], uapi.ByteValueOf(innerVal))
		//api.AssertIsEqual(circuit.PrevTxId[i].Val, innerVal)
	}

	return nil

}
*/
