package groth16

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// export
/* We can use the generic OuterCircuit provided by framework,
it requires :
   Proof, VerifyingKey (to verify the previous proof ? )
   InnerWitness ( containing public inputs for previous proof ? )

*/

// proof of CurrTxId being equal to
// sha256(CurrTxPrefix || PrevTxId || CurrTxPost)
type Sha256InnerCircuit struct {
	//Raw transaction. We will assert that it's previous outpoint
	//
	CurrTxPrefix [512]uints.U8
	CurrTxPost   [512]uints.U8

	//proof of decomposed pre-image from above being equal to the following hash
	PrevTxId [32]uints.U8
	CurrTxId [32]uints.U8 `gnark:",public"`
}

func (circuit *Sha256InnerCircuit) Define(api frontend.API) error {

	//instantiate a sha256 circuit
	sha256, _ := sha2.New(api)

	//b, _ := api.Compiler().NewHint(sha256Hint, 1, circuit.PreImage)
	//fmt.Println(b[0]) // should contain the calculated hash of PreImage

	fullTx := append(circuit.CurrTxPrefix[:], circuit.CurrTxId[:]...)
	fullTx = append(fullTx, circuit.CurrTxPost[:]...)

	//write the preimage into the circuit
	sha256.Write(fullTx[:])

	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	//use the circuit directly to calculate the sha256 hash
	res := sha256.Sum()

	//assert that the circuit calculated correct hash length . Maybe not needed.
	if len(res) != 32 {
		return fmt.Errorf("not 32 bytes")
	}

	//loop over the individual bytes of the calculated hash
	//and compare them to the expected digest
	for i := range circuit.CurrTxId {
		uapi.ByteAssertEq(circuit.CurrTxId[i], res[i])
	}

	return nil
}

type Sha256OuterCircuit[S algebra.ScalarT, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	InnerProof   stdgroth16.Proof[G1El, G2El]
	VerifyingKey stdgroth16.VerifyingKey[G1El, G2El, GtEl]
	InnerWitness stdgroth16.Witness[S] //the currTx for this must be set in-circuit to ensure the bond between the two

	/* The PrevTxId of the Outer Circuit must be matched and equal to the CurrTxId of the InnerProof.
	   Because the InnerProof that we are verifying for the current Transaction
	   was actually generated in/for the parent transaction (in who's context it was the )

	   Furthermore, both of the following must be public, because the verifying wallet
	   will need to look at current Txn, extract these public values.
	   And use them to validate the provided Outer Proof.
	*/
	PrevTxId [32]uints.U8 `gnark:",public"`
	//CurrTxId [32]uints.U8 `gnark:",public"`
}

// Define
// A simple circuit for generating a proof that attests that the
// prover knows the pre-image to a sha256 hash

//	outerCircuit := &OuterCircuit[sw_bls12377.Scalar, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
//		InnerWitness: stdgroth16.PlaceholderWitness[sw_bls12377.Scalar](innerCcs),
//		VerifyingKey: stdgroth16.PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerCcs),
//	}
func (circuit *Sha256OuterCircuit[S, G1El, G2El, GtEl]) Define(api frontend.API) error {

	/**
	Following section of code is copied from the nonnative_doc_test.go example
	*/
	curve, err := algebra.GetCurve[S, G1El](api)
	if err != nil {
		return fmt.Errorf("new curve: %w", err)
	}
	pairing, err := algebra.GetPairing[G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("get pairing: %w", err)
	}
	verifier := stdgroth16.NewVerifier(curve, pairing)

	//set innerWitness.CurrTxId to circuit.PrevTxId
	innerCircuit := &Sha256InnerCircuit{
		CurrTxId: circuit.PrevTxId,
	}
	pubWitness, err := frontend.NewWitness(innerCircuit, ecc.BLS12_377.ScalarField())

	witnessVal, err := stdgroth16.ValueOfWitness[S, G1El](pubWitness)

	witness := stdgroth16.Witness[S]{
		Public: witnessVal.Public,
	}

	err = verifier.AssertProof(circuit.VerifyingKey, circuit.InnerProof, witness) // circuit.InnerWitness

	return err
	//NOTE: Check whether we might need to also mess with the CurrentTxId somehow in the outer proof
	//      I don't think we need to try and explicitly pass that info though. It should be implicitly
	//      carried as public part of Witness in Outer Circuit's Proof (yes ? )

	/*
		The following might be sufficient for the recursive case, since the
		public input (PrevTxId) is provided as part of the Witness of the Outer Circuit along with PrevProof
	*/

	//extract CurrentRawTx[PrevOutpoint]

	//assert that CurrentRawTx[PrevOutpoint] == PrevTxId

}
