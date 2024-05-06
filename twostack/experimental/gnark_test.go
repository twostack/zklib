package experimental

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	native_groth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

type OuterCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        groth16.Proof[G1El, G2El]
	VerifyingKey groth16.VerifyingKey[G1El, G2El, GtEl]
	InnerWitness groth16.Witness[FR]
}

func (c *OuterCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := groth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}

	return verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness, groth16.WithCompleteArithmetic())
}

type InnerCircuit struct {
	RawTx    []uints.U8
	CurrTxId []uints.U8 `gnark:",public"` //probably needs to provide the reversed version to save circuit space
}

func (c *InnerCircuit) Define(api frontend.API) error {

	digester, err := sha2.New(api)
	if err != nil {
		return err
	}

	//write the preimage into the circuit
	digester.Write(c.RawTx)

	//use the circuit directly to calculate the double-sha256 hash
	shaRes := digester.Sum()

	////assert that the circuit calculated correct hash length . Maybe not needed.
	if len(shaRes) != 32 {
		return fmt.Errorf("not 32 bytes")
	}

	uapi, err := uints.New[uints.U32](api)
	for i := range c.CurrTxId {
		uapi.ByteAssertEq(c.CurrTxId[i], shaRes[i])
	}
	//
	//if err != nil {
	//	return err
	//}
	//calculatedTxId, err := calculateSha256(api, firstHash)
	//if err != nil {
	//	return err
	//}
	//
	////assert current public input matches calculated txId
	//uapi, err := uints.New[uints.U32](api)
	//for i := range c.CurrTxId {
	//	uapi.ByteAssertEq(c.CurrTxId[i], calculatedTxId[i])
	//}

	return nil
}

func getInner(assert *test.Assert, field *big.Int) (constraint.ConstraintSystem, native_groth16.VerifyingKey, witness.Witness, native_groth16.Proof) {

	fullTxBytes, _ := hex.DecodeString("0200000001faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71000000006a47304402200ce76e906d995091f28ca40f4579c358bce832cd0d5c5535e4736e4444f6ba2602204fa80867c48e6016b3fa013633ad87203a18487786d8758ee3fe8a6ad5efdf06412103f368e789ce7c6152cc3a36f9c68e69b93934ce0b8596f9cd8032061d5feff4fffeffffff020065cd1d000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac1e64cd1d000000001976a914ce3e1e6345551bed999b48ab8b2ebb1ca880bcda88ac70000000")

	firstHash := sha256.Sum256(fullTxBytes)
	currTxId := sha256.Sum256(firstHash[:])

	innerCirc := &InnerCircuit{}
	copy(innerCirc.CurrTxId[:], make([]uints.U8, 32))
	copy(innerCirc.RawTx[:], make([]uints.U8, len(fullTxBytes)))
	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, innerCirc)
	assert.NoError(err)
	innerPK, innerVK, err := native_groth16.Setup(innerCcs)
	assert.NoError(err)

	//prevTxnIdBytes, _ := hex.DecodeString("faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71")
	// inner proof
	innerAssignment := &InnerCircuit{}
	copy(innerAssignment.CurrTxId[:], uints.NewU8Array(currTxId[:]))
	copy(innerCirc.RawTx[:], uints.NewU8Array(fullTxBytes))
	innerWitness, err := frontend.NewWitness(innerAssignment, field)
	assert.NoError(err)
	innerProof, err := native_groth16.Prove(innerCcs, innerPK, innerWitness)
	assert.NoError(err)
	innerPubWitness, err := innerWitness.Public()
	assert.NoError(err)
	err = native_groth16.Verify(innerProof, innerVK, innerPubWitness)
	assert.NoError(err)
	return innerCcs, innerVK, innerPubWitness, innerProof
}

func TestBLS12InBW6(t *testing.T) {
	assert := test.NewAssert(t)
	innerCcs, innerVK, innerWitness, innerProof := getInner(assert, ecc.BLS12_377.ScalarField())

	// outer proof
	circuitVk, err := groth16.ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVK)
	assert.NoError(err)
	circuitWitness, err := groth16.ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	assert.NoError(err)
	circuitProof, err := groth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: groth16.PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
		Proof:        groth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerCcs),
		//VerifyingKey: circuitVk,
		VerifyingKey: groth16.PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerCcs),
	}
	outerAssignment := &OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}
	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField())
	assert.NoError(err)
}
