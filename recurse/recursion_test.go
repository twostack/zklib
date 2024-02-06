package recurse

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

func TestInnerProofCircuit(t *testing.T) {

	//Deconstructed P2PKH Transaction
	prefixBytes, _ := hex.DecodeString("0200000001")
	prevTxnIdBytes, _ := hex.DecodeString("ae4b7f1769154bb04e9c666a4dbb31eb2ec0c4e01d965cbb1ca4574e7ed40a19")
	postFixBytes, _ := hex.DecodeString("000000004847304402200e993f6bc2319615b662ac7f5882bc78dc35101d1b110a0edf2fd79dea2206c2022017e352e87390227a39b7eae6510cdff9e1cedc8a517e811b90ac6b6fdc8d7d0441feffffff")

	fullTxBytes, _ := hex.DecodeString("0200000001ae4b7f1769154bb04e9c666a4dbb31eb2ec0c4e01d965cbb1ca4574e7ed40a19000000004847304402200e993f6bc2319615b662ac7f5882bc78dc35101d1b110a0edf2fd79dea2206c2022017e352e87390227a39b7eae6510cdff9e1cedc8a517e811b90ac6b6fdc8d7d0441feffffff")

	firstHash := sha256.Sum256(fullTxBytes)
	currTxId := sha256.Sum256(firstHash[:])

	//full witness
	witness := Sha256InnerCircuit{}
	copy(witness.PrevTxId[:], uints.NewU8Array(prevTxnIdBytes))
	copy(witness.CurrTxPost[:], uints.NewU8Array(postFixBytes))
	copy(witness.CurrTxPrefix[:], uints.NewU8Array(prefixBytes))
	copy(witness.CurrTxId[:], uints.NewU8Array(currTxId[:]))

	// inner circuit pre-image values only
	testCircuit := Sha256InnerCircuit{}
	copy(testCircuit.PrevTxId[:], uints.NewU8Array(prevTxnIdBytes))
	copy(testCircuit.CurrTxPost[:], uints.NewU8Array(postFixBytes))
	copy(testCircuit.CurrTxPrefix[:], uints.NewU8Array(prefixBytes))

	//test circuit execution
	err := test.IsSolved(&testCircuit, &witness, ecc.BLS12_377.ScalarField())

	if err != nil {
		t.Fatal(err)
	}

	//test the prover
	assert := test.NewAssert(t)

	proverCircuit := Sha256InnerCircuit{}
	copy(proverCircuit.CurrTxId[:], uints.NewU8Array(currTxId[:]))
	copy(proverCircuit.PrevTxId[:], uints.NewU8Array(prevTxnIdBytes))
	copy(proverCircuit.CurrTxPost[:], uints.NewU8Array(postFixBytes))
	copy(proverCircuit.CurrTxPrefix[:], uints.NewU8Array(prefixBytes))

	assert.ProverSucceeded(&Sha256InnerCircuit{}, &proverCircuit, test.WithCurves(ecc.BLS12_377))

}

func TestInnerProof2(t *testing.T) {
	//innerCcs, innerVK, innerWitness, innerProof :=
	computeInnerProof(ecc.BLS12_377.ScalarField())

}

// computeInnerProof computes the proof for the inner circuit we want to verify
// recursively. In this example the Groth16 keys are generated on the fly, but
// in practice should be genrated once and using MPC.
func computeInnerProof(field *big.Int) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {
	/*
		innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &Sha256InnerCircuit{})
		if err != nil {
			panic(err)
		}
		// NB! UNSAFE! Use MPC.
		innerPK, innerVK, err := groth16.Setup(innerCcs)
		if err != nil {
			panic(err)
		}

		//currTxId := []byte("ac2ed2a0a9fabd31b9d0165a0f2fdc6e4daf3469149f7e2de83a88a6f8783a19") //reversed TxId

		prefix := []byte("0200000001")

		currTxId := sha256.Sum256(prefix) //reversed TxId

		prevTxnId := []byte("ae4b7f1769154bb04e9c666a4dbb31eb2ec0c4e01d965cbb1ca4574e7ed40a19")
		postFix := []byte("000000004847304402200e993f6bc2319615b662ac7f5882bc78dc35101d1b110a0edf2fd79dea2206c2022017e352e87390227a39b7eae6510cdff9e1cedc8a517e811b90ac6b6fdc8d7d0441feffffff")
		//prefix : 0200000001
		//prevTxnId : ae4b7f1769154bb04e9c666a4dbb31eb2ec0c4e01d965cbb1ca4574e7ed40a19
		//postFix :  000000004847304402200e993f6bc2319615b662ac7f5882bc78dc35101d1b110a0edf2fd79dea2206c2022017e352e87390227a39b7eae6510cdff9e1cedc8a517e811b90ac6b6fdc8d7d0441feffffff

		// inner proof
		innerAssignment := &Sha256InnerCircuit{}

		copy(innerAssignment.CurrTxPrefix[:], uints.NewU8Array(prefix[:]))
		copy(innerAssignment.CurrTxPost[:], uints.NewU8Array(postFix[:]))
		copy(innerAssignment.PrevTxId[:], uints.NewU8Array(prevTxnId[:]))
		copy(innerAssignment.CurrTxId[:], uints.NewU8Array(currTxId[:]))

		innerWitness, err := frontend.NewWitness(innerAssignment, field)
		if err != nil {
			panic(err)
		}
		innerProof, err := groth16.Prove(innerCcs, innerPK, innerWitness)
		if err != nil {
			panic(err)
		}
		innerPubWitness, err := innerWitness.Public()
		if err != nil {
			panic(err)
		}
		err = groth16.Verify(innerProof, innerVK, innerPubWitness)
		if err != nil {
			panic(err)
		}


		return innerCcs, innerVK, innerPubWitness, innerProof
	*/
	return nil, nil, nil, nil
}
