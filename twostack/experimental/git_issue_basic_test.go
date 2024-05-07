package experimental

/**
NOTE: This code is taken (and modified) from a reported Github issue on the gnark board.

Reproduced here for internal testing and verification.

https://github.com/Consensys/gnark/issues/1079


This test fails at the end of the in-circuit proof verifier. It attempts
to match pairings, and fails.

Error at --- > std/recursion/groth16/verifier.go : line 665

Currently fails :
    git_issue_sha256_mod_test.go:199:
        	Error Trace:	/Users/stephanfebruary/IdeaProjects/zklib/twostack/experimental/git_issue_sha256_mod_test.go:199
        	Error:      	Received unexpected error:
        	            	[assertIsEqual] 246911385926790084676521132327533278724172104698513407034219432829442646692225982363073196559508426744023449281697 == 178019439188757268520945169744054423925444462796904837538274209893135190916488394525540979064023104574358501473579
        	            	fields_bls12377.(*E2).AssertIsEqual
        	            		e2.go:196

At end of AssertProof() method it fails to match the pairings
*/
import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

type innerCircuit struct {
	PreImage [191]frontend.Variable //probably needs to provide the reversed version to save circuit space
	TxId     [32]frontend.Variable  `gnark:",public"` //probably needs to provide the reversed version to save circuit space
}

func (c *innerCircuit) Define(api frontend.API) error {

	uapi, err := uints.New[uints.U32](api)
	preImageArr := make([]uints.U8, len(c.PreImage))

	for ndx := range c.PreImage {
		preImageArr[ndx] = uapi.ByteValueOf(c.PreImage[ndx])
	}
	txIdArr := make([]uints.U8, len(c.PreImage))
	for ndx := range c.TxId {
		txIdArr[ndx] = uapi.ByteValueOf(c.TxId[ndx])
	}

	firstHash, err := calculateSha256(api, preImageArr[:])
	if err != nil {
		return err
	}
	_, err = calculateSha256(api, firstHash)
	if err != nil {
		return err
	}

	//assert current public input matches calculated txId
	//uapi, err := uints.New[uints.U32](api)
	//for i := range circuit.CurrTxId {
	//	uapi.ByteAssertEq(circuit.CurrTxId[i], calculatedTxId[i])
	//}

	return nil
}

// outerCircuit is the generic outer circuit which can verify Groth16 proofs
// using field emulation or 2-chains of curves.
type outerCircuitGI[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        stdgroth16.Proof[G1El, G2El]
	VerifyingKey stdgroth16.VerifyingKey[G1El, G2El, GtEl]
	InnerWitness stdgroth16.Witness[FR]
}

func (c *outerCircuitGI[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	err = verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
	return err
}

func getInnerBasicCircuit(outerField, innerField *big.Int, xVal int, yVal int) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof, error) {
	//make the compiler happy
	circuit := innerCircuit{
		//TxId: make([]uints.U8, 32),
	}

	innerCcs, err := frontend.Compile(innerField, r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("One")
		return nil, nil, nil, nil, err
	}

	innerPK, innerVK, err := groth16.Setup(innerCcs)
	if err != nil {
		fmt.Println("Two")
		return nil, nil, nil, nil, err
	}

	pi, _ := hex.DecodeString("0200000001ae4b7f1769154bb04e9c666a4dbb31eb2ec0c4e01d965cbb1ca4574e7ed40a19000000004847304402200e993f6bc2319615b662ac7f5882bc78dc35101d1b110a0edf2fd79dea2206c2022017e352e87390227a39b7eae6510cdff9e1cedc8a517e811b90ac6b6fdc8d7d0441feffffff0200ca9a3b000000001976a914783b608b9278a187641d047c14dbf63e1be5bc8888ac00196bee000000001976a9142bfccc428186e69fc94fde6d7396f19482dd5a7988ac65000000")
	firstHash := sha256.Sum256(pi)

	// inner proof
	innerAssignment := &innerCircuit{}
	for ndx := range pi {
		innerAssignment.PreImage[ndx] = pi[ndx]
	}
	for ndx := range firstHash {
		innerAssignment.TxId[ndx] = firstHash[ndx]
	}
	//copy(innerAssignment.PreImage[:], uints.NewU8Array(pi))
	//copy(innerAssignment.TxId[:], uints.NewU8Array(firstHash[:]))
	innerWitness, err := frontend.NewWitness(innerAssignment, innerField)
	if err != nil {
		fmt.Println("Three")
		return nil, nil, nil, nil, err
	}
	innerProof, err := groth16.Prove(innerCcs, innerPK, innerWitness, stdgroth16.GetNativeProverOptions(outerField, innerField))
	if err != nil {
		fmt.Println("Five")
		return nil, nil, nil, nil, err
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		fmt.Println("Six")
		return nil, nil, nil, nil, err
	}
	err = groth16.Verify(innerProof, innerVK, innerPubWitness, stdgroth16.GetNativeVerifierOptions(outerField, innerField))
	if err != nil {
		fmt.Println("seven")
		return nil, nil, nil, nil, err
	}

	return innerCcs, innerVK, innerPubWitness, innerProof, nil
}

func TestRecursiveCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	innerCcs, innerVK, innerPubWitness, innerProof, err := getInnerBasicCircuit(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField(), 5, 5)
	assert.NoError(err)
	// initialize the witness elements
	circuitVk, err := stdgroth16.ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVK)
	assert.NoError(err)
	circuitPubWitness, err := stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](innerPubWitness)
	//fmt.Printf("nbInnerPubWitness:%v, witness:%v\n", len(circuitPubWitness.Public), circuitPubWitness.Public)

	assert.NoError(err)
	circuitProof, err := stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	assert.NoError(err)

	outerAssignment := &outerCircuitGI[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitPubWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}

	// the witness size depends on the number of public variables. We use the
	// compiled inner circuit to deduce the required size for the outer witness
	// using functions [stdgroth16.PlaceholderWitness] and
	// [stdgroth16.PlaceholderVerifyingKey]
	outerCircuit := &outerCircuitGI[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
		Proof:        stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerCcs),
		VerifyingKey: stdgroth16.PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerCcs),
	}

	err = test.IsSolved(outerCircuit, outerAssignment, ecc.BW6_761.ScalarField())
	assert.NoError(err)

	//// compile the outer circuit
	//outerCcs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, outerCircuit)
	//assert.NoError(err)
	//// create prover witness from the assignment
	//outerWitness, err := frontend.NewWitness(outerAssignment, ecc.BW6_761.ScalarField())
	//assert.NoError(err)

	//// create public witness from the assignment
	//outerPublicWitness, err := outerWitness.Public()
	//assert.NoError(err)

	//// create Groth16 setup. NB! UNSAFE
	//outerPk, outerVk, err := groth16.Setup(outerCcs) // UNSAFE! Use MPC
	//assert.NoError(err)
	//
	//// construct the groth16 proof of verifying Groth16 proof in-circuit
	//outerProof, err := groth16.Prove(outerCcs, outerPk, outerWitness)
	//assert.NoError(err)
	//
	//// verify the Groth16 proof
	//err = groth16.Verify(outerProof, outerVk, outerPublicWitness)
	//assert.NoError(err)

}

func calculateSha256(api frontend.API, preImage []uints.U8) ([]uints.U8, error) {
	//instantiate a sha256 circuit
	h, err := sha2.New(api)

	if err != nil {
		return nil, err
	}

	//write the preimage into the circuit
	h.Write(preImage)

	//use the circuit directly to calculate the double-sha256 hash
	res := h.Sum()

	//assert that the circuit calculated correct hash length . Maybe not needed.
	if len(res) != 32 {
		return nil, fmt.Errorf("not 32 bytes")
	}
	return res, nil
}
