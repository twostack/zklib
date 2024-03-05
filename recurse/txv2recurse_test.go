package recurse

import (
	"crypto/sha256"
	"encoding/hex"
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

func TestBaseCase(t *testing.T) {

	assert := test.NewAssert(t)

	innerField := ecc.BLS12_377.ScalarField()
	outerField := ecc.BLS12_377.ScalarField()

	innerCcs, provingKey, verifyingKey, err := setupBaseCase(innerField)
	if err != nil {
		panic(err)
	}

	fullTxBytes, _ := hex.DecodeString("020000000190bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")
	prefixBytes, _ := hex.DecodeString("0200000001")
	prevTxnIdBytes, _ := hex.DecodeString("90bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7")
	postFixBytes, _ := hex.DecodeString("000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")

	firstHash := sha256.Sum256(fullTxBytes)
	genesisTxId := sha256.Sum256(firstHash[:])

	//fmt.Println(hex.EncodeToString(genesisTxId[:]))
	// create full genesis witness (placeholders, prevTxnIdBytes is empty
	//vk, err := plonk.ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](verifyingKey)
	genesisWitness, err := createBaseCaseWitness(prefixBytes, postFixBytes, prevTxnIdBytes, genesisTxId)

	assert.NoError(err)
	genesisProof, err := native_plonk.Prove(innerCcs, provingKey, genesisWitness, plonk.GetNativeProverOptions(outerField, innerField))

	//verify the genesis proof
	assert.NoError(err)
	publicWitness, err := genesisWitness.Public()
	assert.NoError(err)
	err = native_plonk.Verify(genesisProof, verifyingKey, publicWitness, plonk.GetNativeVerifierOptions(outerField, innerField))
	assert.NoError(err)
}

// circuitVk plonk.VerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine],
func createBaseCaseProof() (
	native_plonk.VerifyingKey,
	native_plonk.Proof) {

	innerField := ecc.BLS12_377.ScalarField()
	outerField := ecc.BLS12_377.ScalarField()

	innerCcs, provingKey, verifyingKey, err := setupBaseCase(innerField)
	if err != nil {
		panic(err)
	}

	fullTxBytes, _ := hex.DecodeString("020000000190bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")
	prefixBytes, _ := hex.DecodeString("0200000001")
	prevTxnIdBytes, _ := hex.DecodeString("90bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7")
	postFixBytes, _ := hex.DecodeString("000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")

	firstHash := sha256.Sum256(fullTxBytes)
	genesisTxId := sha256.Sum256(firstHash[:])

	//fmt.Println(hex.EncodeToString(genesisTxId[:]))
	// create full genesis witness (placeholders, prevTxnIdBytes is empty
	//vk, err := plonk.ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](verifyingKey)
	genesisWitness, err := createBaseCaseWitness(prefixBytes, postFixBytes, prevTxnIdBytes, genesisTxId)

	proof, err := native_plonk.Prove(innerCcs, provingKey, genesisWitness, plonk.GetNativeProverOptions(outerField, innerField))

	return verifyingKey, proof
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
	prevTxnIdBytes, _ := hex.DecodeString("faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71")
	postFixBytes, _ := hex.DecodeString("000000006a47304402200ce76e906d995091f28ca40f4579c358bce832cd0d5c5535e4736e4444f6ba2602204fa80867c48e6016b3fa013633ad87203a18487786d8758ee3fe8a6ad5efdf06412103f368e789ce7c6152cc3a36f9c68e69b93934ce0b8596f9cd8032061d5feff4fffeffffff020065cd1d000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac1e64cd1d000000001976a914ce3e1e6345551bed999b48ab8b2ebb1ca880bcda88ac70000000")

	fullTxBytes, _ := hex.DecodeString("0200000001faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71000000006a47304402200ce76e906d995091f28ca40f4579c358bce832cd0d5c5535e4736e4444f6ba2602204fa80867c48e6016b3fa013633ad87203a18487786d8758ee3fe8a6ad5efdf06412103f368e789ce7c6152cc3a36f9c68e69b93934ce0b8596f9cd8032061d5feff4fffeffffff020065cd1d000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac1e64cd1d000000001976a914ce3e1e6345551bed999b48ab8b2ebb1ca880bcda88ac70000000")

	firstHash := sha256.Sum256(fullTxBytes)
	currTxId := sha256.Sum256(firstHash[:])

	//fmt.Println(hex.EncodeToString(genesisTxId[:]))
	// create full genesis witness (placeholders, prevTxnIdBytes is empty
	innerAssignment := Sha256CircuitBaseCase[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G1Affine, sw_bls12377.GT]{}

	//assign the current Txn data
	copy(innerAssignment.CurrTxId[:], uints.NewU8Array(prevTxnIdBytes[:])) //coincidentally that in this test prev txn is issuance
	copy(innerAssignment.TokenId[:], uints.NewU8Array(prevTxnIdBytes[:]))  //base case tokenId == txId
	previousWitness, err := frontend.NewWitness(&innerAssignment, ecc.BLS12_377.ScalarField())

	verifyingKey, previousProof := createBaseCaseProof()

	innerWitness, err := plonk.ValueOfWitness[sw_bls12377.ScalarField](previousWitness) //FIXME: Check if this breaks because witness structure sizes
	innerProof, err := plonk.ValueOfProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](previousProof)

	vk, err := plonk.ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](verifyingKey)

	tokenId := [32]byte{}

	copy(tokenId[:], prevTxnIdBytes)
	genesisWitness, err := createFullWitness(innerWitness, innerProof, vk, prefixBytes, postFixBytes, prevTxnIdBytes, currTxId, tokenId /*tokenid*/, innerField)

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

func createBaseCaseWitness(
	prefixBytes []byte,
	postFixBytes []byte,
	prevTxnIdBytes []byte,
	currTxId [32]byte,
) (witness.Witness, error) {

	innerAssignment := Sha256CircuitBaseCase[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G1Affine, sw_bls12377.GT]{}

	//assign the current Txn data
	copy(innerAssignment.CurrTxPrefix[:], uints.NewU8Array(prefixBytes))
	copy(innerAssignment.CurrTxPost[:], uints.NewU8Array(postFixBytes))
	copy(innerAssignment.PrevTxId[:], uints.NewU8Array(prevTxnIdBytes))
	copy(innerAssignment.CurrTxId[:], uints.NewU8Array(currTxId[:]))
	copy(innerAssignment.TokenId[:], uints.NewU8Array(currTxId[:])) //base case tokenId == txId

	innerWitness, err := frontend.NewWitness(&innerAssignment, ecc.BLS12_377.ScalarField())
	if err != nil {
		return nil, err
	}
	return innerWitness, nil
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
