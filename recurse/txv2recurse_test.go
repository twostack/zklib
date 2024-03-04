package recurse

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
	"math/big"
	"testing"
)

func computeGenesisProof() {

}

func TestInitialRecursion(t *testing.T) {

	assert := test.NewAssert(t)

	innerField := ecc.BLS12_377.ScalarField()
	outerField := ecc.BLS12_377.ScalarField()

	//innerCcs, provingKey, verifyingKey, err := setupCircuitParams(innerField)
	innerCcs, provingKey, verifyingKey, err := setupBaseCase(innerField)
	if err != nil {
		panic(err)
	}

	prefixBytes, _ := hex.DecodeString("0200000001")
	//prevTxnIdBytes, _ := hex.DecodeString("ae4b7f1769154bb04e9c666a4dbb31eb2ec0c4e01d965cbb1ca4574e7ed40a19")
	postFixBytes, _ := hex.DecodeString("000000004847304402200e993f6bc2319615b662ac7f5882bc78dc35101d1b110a0edf2fd79dea2206c2022017e352e87390227a39b7eae6510cdff9e1cedc8a517e811b90ac6b6fdc8d7d0441feffffff0200ca9a3b000000001976a914783b608b9278a187641d047c14dbf63e1be5bc8888ac00196bee000000001976a9142bfccc428186e69fc94fde6d7396f19482dd5a7988ac65000000")

	fullTxBytes, _ := hex.DecodeString("0200000001ae4b7f1769154bb04e9c666a4dbb31eb2ec0c4e01d965cbb1ca4574e7ed40a19000000004847304402200e993f6bc2319615b662ac7f5882bc78dc35101d1b110a0edf2fd79dea2206c2022017e352e87390227a39b7eae6510cdff9e1cedc8a517e811b90ac6b6fdc8d7d0441feffffff0200ca9a3b000000001976a914783b608b9278a187641d047c14dbf63e1be5bc8888ac00196bee000000001976a9142bfccc428186e69fc94fde6d7396f19482dd5a7988ac65000000")

	firstHash := sha256.Sum256(fullTxBytes)
	genesisTxId := sha256.Sum256(firstHash[:])

	fmt.Println(hex.EncodeToString(genesisTxId[:]))
	// create full genesis witness (placeholders, prevTxnIdBytes is empty
	genesisPrevTxnIdBytes := make([]byte, 32)
	previousWitness := plonk.PlaceholderWitness[sw_bls12377.ScalarField](innerCcs)
	previousProof := plonk.PlaceholderProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerCcs)
	vk, err := plonk.ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](verifyingKey)
	genesisWitness, err := createFullWitness(previousWitness, previousProof, vk, prefixBytes, postFixBytes, genesisPrevTxnIdBytes, genesisTxId, genesisTxId /*tokenid*/, innerField)

	assert.NoError(err)
	genesisProof, err := native_plonk.Prove(innerCcs, provingKey, genesisWitness, plonk.GetNativeProverOptions(outerField, innerField))

	//verify the genesis proof
	assert.NoError(err)
	publicWitness, err := genesisWitness.Public()
	assert.NoError(err)
	err = native_plonk.Verify(genesisProof, verifyingKey, publicWitness, plonk.GetNativeVerifierOptions(outerField, innerField))
	assert.NoError(err)

	//Let's do the first issuance , proof, vk
	//gw, err := plonk.ValueOfWitness[sw_bls12377.ScalarField](genesisWitness)
	//issuanceWitness, err := createFullWitness(gw, previousProof, vk, prefixBytes, postFixBytes, genesisPrevTxnIdBytes, genesisTxId, innerField)
	//issuanceProof, err := native_plonk.Prove(innerCcs, provingKey, genesisWitness, plonk.GetNativeProverOptions(outerField, innerField))
}

func createFullWitness(
	circuitWitness plonk.Witness[sw_bls12377.ScalarField],
	circuitProof plonk.Proof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine],
	circuitVk plonk.VerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine],
	prefixBytes []byte,
	postFixBytes []byte,
	prevTxnIdBytes []byte,
	currTxId [32]byte,
	tokenId [32]byte,
	innerField *big.Int) (witness.Witness, error) {

	innerAssignment := Sha256Circuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		PreviousWitness: circuitWitness,
		PreviousProof:   circuitProof,
		PreviousVk:      circuitVk,
	}

	//assign the previous proof data

	//assign the current Txn data
	copy(innerAssignment.CurrTxPrefix[:], uints.NewU8Array(prefixBytes))
	copy(innerAssignment.CurrTxPost[:], uints.NewU8Array(postFixBytes))
	copy(innerAssignment.PrevTxId[:], uints.NewU8Array(prevTxnIdBytes))
	copy(innerAssignment.CurrTxId[:], uints.NewU8Array(currTxId[:]))
	copy(innerAssignment.TokenId[:], uints.NewU8Array(tokenId[:]))

	innerWitness, err := frontend.NewWitness(&innerAssignment, innerField)
	if err != nil {
		return nil, err
	}
	return innerWitness, nil
}

func setupBaseCase(innerField *big.Int) (constraint.ConstraintSystem, native_plonk.ProvingKey, native_plonk.VerifyingKey, error) {

	baseCcs, err := frontend.Compile(innerField, scs.NewBuilder,
		&Sha256CircuitBaseCase[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G1Affine, sw_bls12377.GT]{})

	if err != nil {
		return nil, nil, nil, err
	}

	srs, srsLagrange, err := unsafekzg.NewSRS(baseCcs)

	if err != nil {
		return nil, nil, nil, err
	}

	innerPK, innerVK, err := native_plonk.Setup(baseCcs, srs, srsLagrange)
	if err != nil {
		return nil, nil, nil, err
	}
	return baseCcs, innerPK, innerVK, nil
}

func setupCircuitParams(innerField *big.Int) (constraint.ConstraintSystem, native_plonk.ProvingKey, native_plonk.VerifyingKey, error) {

	innerCcs, err := frontend.Compile(innerField, scs.NewBuilder,
		&Sha256Circuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G1Affine, sw_bls12377.GT]{})

	if err != nil {
		return nil, nil, nil, err
	}

	srs, srsLagrange, err := unsafekzg.NewSRS(innerCcs)

	if err != nil {
		return nil, nil, nil, err
	}

	innerPK, innerVK, err := native_plonk.Setup(innerCcs, srs, srsLagrange)
	if err != nil {
		return nil, nil, nil, err
	}
	return innerCcs, innerPK, innerVK, nil
}
