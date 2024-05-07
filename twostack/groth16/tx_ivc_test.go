package txivc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	native_groth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"testing"
	"time"
)

func TestBaseCase(t *testing.T) {

	assert := test.NewAssert(t)

	fullTxBytes, _ := hex.DecodeString("020000000190bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")

	start := time.Now()
	innerCcs, provingKey, verifyingKey, err := SetupBaseCase(len(fullTxBytes), ecc.BLS12_377.ScalarField())
	if err != nil {
		panic(err)
	}
	elapsed := time.Since(start)
	fmt.Printf("Setup took %s to complete \n", elapsed)

	firstHash := sha256.Sum256(fullTxBytes)
	genesisTxId := sha256.Sum256(firstHash[:])

	//fmt.Println(hex.EncodeToString(genesisTxId[:]))
	// create full genesis witness (placeholders, prevTxnIdBytes is empty
	//vk, err := plonk.ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](verifyingKey)
	genesisWitness, err := CreateBaseCaseFullWitness(fullTxBytes, genesisTxId)

	start = time.Now()
	assert.NoError(err)
	genesisProof, err := native_groth16.Prove(innerCcs, provingKey, genesisWitness, groth16.GetNativeProverOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
	elapsed = time.Since(start)
	fmt.Printf("The prover took %s to complete \n", elapsed)

	//verify the genesis proof
	assert.NoError(err)
	publicWitness, err := genesisWitness.Public()
	assert.NoError(err)
	err = native_groth16.Verify(genesisProof, verifyingKey, publicWitness, groth16.GetNativeVerifierOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
	assert.NoError(err)
}

func TestShowHash(t *testing.T) {

	fullTxBytes, _ := hex.DecodeString("020000000190bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")

	firstHash := sha256.Sum256(fullTxBytes)
	secondHash := sha256.Sum256(firstHash[:])

	fmt.Printf("hash: %s\n", hex.EncodeToString(secondHash[:]))
}

func TestNormalCase(t *testing.T) {

	assert := test.NewAssert(t)

	//innerField := ecc.BLS24_315.ScalarField()
	//outerField := ecc.BW6_633.ScalarField()
	innerField := ecc.BLS12_377.ScalarField()
	outerField := ecc.BW6_761.ScalarField()
	proverOptions := groth16.GetNativeProverOptions(outerField, innerField)

	fullTxBytes, _ := hex.DecodeString("020000000190bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")

	start := time.Now()
	baseCcs, basePk, baseVk, err := SetupBaseCase(len(fullTxBytes), innerField)
	end := time.Since(start)
	fmt.Printf("Setup Base Case took : %s\n", end)

	firstHash := sha256.Sum256(fullTxBytes)
	secondHash := sha256.Sum256(firstHash[:])

	genesisWitness, err := CreateBaseCaseFullWitness(fullTxBytes, secondHash)

	start = time.Now()
	genesisProof, err := native_groth16.Prove(baseCcs, basePk, genesisWitness, proverOptions)
	end = time.Since(start)
	fmt.Printf("Base Case Proof took : %s\n", end)

	//can create a lightweight witness here for verification
	//err := native_plonk.Verify(genesisProof, verifyingKey, genesisWitness, plonk.GetNativeVerifierOptions(outerField, innerField))
	pubWitness, err := genesisWitness.Public()
	assert.NoError(err)

	err = native_groth16.Verify(genesisProof, baseVk, pubWitness, groth16.GetNativeVerifierOptions(outerField, innerField))
	assert.NoError(err)
	fmt.Printf("Base Case Proof Verified!\n")

	//outerField := ecc.BW6_761.ScalarField()
	innerWitness, err := groth16.ValueOfWitness[sw_bls12377.ScalarField](pubWitness)
	innerProof, err := groth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](genesisProof)
	innerVk, err := groth16.ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](baseVk)

	//spending tx info. Re-use vars from genesis
	prefixBytes, _ := hex.DecodeString("0200000001")
	prevTxnIdBytes, _ := hex.DecodeString("faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71")
	postFixBytes, _ := hex.DecodeString("000000006a47304402200ce76e906d995091f28ca40f4579c358bce832cd0d5c5535e4736e4444f6ba2602204fa80867c48e6016b3fa013633ad87203a18487786d8758ee3fe8a6ad5efdf06412103f368e789ce7c6152cc3a36f9c68e69b93934ce0b8596f9cd8032061d5feff4fffeffffff020065cd1d000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac1e64cd1d000000001976a914ce3e1e6345551bed999b48ab8b2ebb1ca880bcda88ac70000000")
	fullTxBytes, _ = hex.DecodeString("0200000001faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71000000006a47304402200ce76e906d995091f28ca40f4579c358bce832cd0d5c5535e4736e4444f6ba2602204fa80867c48e6016b3fa013633ad87203a18487786d8758ee3fe8a6ad5efdf06412103f368e789ce7c6152cc3a36f9c68e69b93934ce0b8596f9cd8032061d5feff4fffeffffff020065cd1d000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac1e64cd1d000000001976a914ce3e1e6345551bed999b48ab8b2ebb1ca880bcda88ac70000000")

	firstHash = sha256.Sum256(fullTxBytes)
	currTxId := sha256.Sum256(firstHash[:])
	outerAssignment := CreateOuterAssignment(innerWitness, innerProof, innerVk, prefixBytes, prevTxnIdBytes, postFixBytes, currTxId[:])

	outerWitness, err := frontend.NewWitness(&outerAssignment, outerField)

	start = time.Now()
	outerCcs, outerProvingKey, outerVerifyingKey, err := SetupNormalCase(outerField, &baseCcs, &baseVk)
	assert.NoError(err)
	end = time.Since(start)
	fmt.Printf("Normal case setup took : %s\n", end)

	start = time.Now()
	outerProof, err := native_groth16.Prove(outerCcs, outerProvingKey, outerWitness, groth16.GetNativeProverOptions(outerField, innerField))
	assert.NoError(err)
	end = time.Since(start)
	fmt.Printf("Normal case Proof took : %s\n", end)

	//verify the normal proof
	start = time.Now()
	publicWitness, err := outerWitness.Public()
	assert.NoError(err)
	err = native_groth16.Verify(outerProof, outerVerifyingKey, publicWitness, groth16.GetNativeVerifierOptions(outerField, innerField))
	assert.NoError(err)

	end = time.Since(start)
	fmt.Printf("Normal case verification took : %s\n", end)

	//Let's do the first issuance , proof, vk
	//gw, err := plonk.ValueOfWitness[sw_bls12377.ScalarField](genesisWitness)
	//issuanceWitness, err := createFullWitness(gw, previousProof, vk, prefixBytes, postFixBytes, genesisPrevTxnIdBytes, genesisTxId, innerField)
	//issuanceProof, err := native_plonk.Prove(innerCcs, provingKey, genesisWitness, plonk.GetNativeProverOptions(outerField, innerField))
}

func TestNormalCaseSuccint(t *testing.T) {

	//innerCcs, innerVK, innerWitness, innerProof := computeInnerProof(ecc.BLS12_377.ScalarField())
	//computeInnerProofPlonk(ecc.BLS12_377.ScalarField())

	//issuance txn
	fullTxGenesisBytes, _ := hex.DecodeString("020000000190bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")

	firstHash := sha256.Sum256(fullTxGenesisBytes)
	genesisTxId := sha256.Sum256(firstHash[:])
	txIdStr := hex.EncodeToString(genesisTxId[:])
	fmt.Printf("TxID of Genesis : [%s]\n", txIdStr)

	genesisWitness, err := CreateBaseCaseFullWitness(fullTxGenesisBytes, genesisTxId)

	//innerCcs, innerVK, innerWitness, innerProof :=
	assert := test.NewAssert(t)
	baseCcs, basePk, baseVk, err := SetupBaseCase(len(fullTxGenesisBytes), ecc.BLS12_377.ScalarField())

	innerProof, err := native_groth16.Prove(baseCcs, basePk, genesisWitness, groth16.GetNativeProverOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
	//innerProof, err := zklib.CreateBaseCaseProof(&NormalProofInfo{})
	assert.NoError(err)

	circuitVk, err := groth16.ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](baseVk)
	assert.NoError(err)
	circuitWitness, err := groth16.ValueOfWitness[sw_bls12377.ScalarField](genesisWitness)
	assert.NoError(err)
	circuitProof, err := groth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	assert.NoError(err)

	outerCircuit := &Sha256Circuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		PreviousProof:   groth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](baseCcs),
		PreviousVk:      groth16.PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](baseCcs),
		PreviousWitness: groth16.PlaceholderWitness[sw_bls12377.ScalarField](baseCcs),
	}

	//spending transaction
	prefixBytes, _ := hex.DecodeString("0200000001")
	prevTxnIdBytes, _ := hex.DecodeString("faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71")
	postFixBytes, _ := hex.DecodeString("000000006a47304402200ce76e906d995091f28ca40f4579c358bce832cd0d5c5535e4736e4444f6ba2602204fa80867c48e6016b3fa013633ad87203a18487786d8758ee3fe8a6ad5efdf06412103f368e789ce7c6152cc3a36f9c68e69b93934ce0b8596f9cd8032061d5feff4fffeffffff020065cd1d000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac1e64cd1d000000001976a914ce3e1e6345551bed999b48ab8b2ebb1ca880bcda88ac70000000")

	fullTxBytes, _ := hex.DecodeString("0200000001faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71000000006a47304402200ce76e906d995091f28ca40f4579c358bce832cd0d5c5535e4736e4444f6ba2602204fa80867c48e6016b3fa013633ad87203a18487786d8758ee3fe8a6ad5efdf06412103f368e789ce7c6152cc3a36f9c68e69b93934ce0b8596f9cd8032061d5feff4fffeffffff020065cd1d000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac1e64cd1d000000001976a914ce3e1e6345551bed999b48ab8b2ebb1ca880bcda88ac70000000")

	firstHash = sha256.Sum256(fullTxBytes)
	currTxId := sha256.Sum256(firstHash[:])

	outerAssignment := Sha256Circuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		PreviousWitness: circuitWitness,
		PreviousProof:   circuitProof,
		PreviousVk:      circuitVk,

		CurrTxPrefix: make([]frontend.Variable, len(prefixBytes)),
		CurrTxPost:   make([]frontend.Variable, len(postFixBytes)),
		PrevTxId:     make([]frontend.Variable, len(prevTxnIdBytes)),
		CurrTxId:     make([]frontend.Variable, len(currTxId)),
	}
	for ndx := range prefixBytes {
		outerAssignment.CurrTxPrefix[ndx] = prefixBytes[ndx]
	}
	for ndx := range postFixBytes {
		outerAssignment.CurrTxPost[ndx] = postFixBytes[ndx]
	}
	for ndx := range prevTxnIdBytes {
		outerAssignment.PrevTxId[ndx] = prevTxnIdBytes[ndx]
	}
	for ndx := range currTxId {
		outerAssignment.CurrTxId[ndx] = currTxId[ndx]
	}

	//pubWitness, err := CreateBaseCaseLightWitness(genesisTxId[:], innerField)
	//pw, err := groth16.ValueOfWitness[ScalarField](*pubWitness)
	//outerAssignment := CreateOuterAssignment(pw, circuitProof, circuitVk, prefixBytes, prevTxnIdBytes, postFixBytes, currTxId[:])

	err = test.IsSolved(outerCircuit, &outerAssignment, ecc.BW6_761.ScalarField())
	assert.NoError(err)

	//now follow-up with a first-spend and proof of the previous token

}
