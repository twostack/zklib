package txivc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	native_groth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	"testing"
	"time"
)

func TestBaseCase(t *testing.T) {

	assert := test.NewAssert(t)

	innerField := ecc.BLS24_315.ScalarField()
	outerField := ecc.BW6_633.ScalarField()

	//innerField := ecc.BLS12_377.ScalarField()
	//outerField := ecc.BLS12_377.ScalarField()

	innerCcs, provingKey, verifyingKey, err := SetupBaseCase(innerField)
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
	genesisWitness, err := CreateBaseCaseWitness(prefixBytes, postFixBytes, prevTxnIdBytes, genesisTxId, innerField)

	assert.NoError(err)
	genesisProof, err := native_groth16.Prove(innerCcs, provingKey, genesisWitness, groth16.GetNativeProverOptions(outerField, innerField))

	//verify the genesis proof
	assert.NoError(err)
	publicWitness, err := genesisWitness.Public()
	assert.NoError(err)
	err = native_groth16.Verify(genesisProof, verifyingKey, publicWitness, groth16.GetNativeVerifierOptions(outerField, innerField))
	assert.NoError(err)
}

func TestNormalCase(t *testing.T) {

	assert := test.NewAssert(t)

	innerField := ecc.BLS24_315.ScalarField()
	outerField := ecc.BW6_633.ScalarField()
	//innerField := ecc.BLS12_377.ScalarField()
	//outerField := ecc.BW6_761.ScalarField()

	fullTxBytes, _ := hex.DecodeString("020000000190bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")
	prefixBytes, _ := hex.DecodeString("0200000001")
	prevTxnIdBytes, _ := hex.DecodeString("90bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7")
	postFixBytes, _ := hex.DecodeString("000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")

	start := time.Now()
	baseCcs, basePk, baseVk, err := SetupBaseCase(innerField)
	end := time.Since(start)
	fmt.Printf("Setup Base Case took : %s\n", end)

	start = time.Now()
	genesisWitness, genesisProof, err := CreateBaseCaseProof(outerField, innerField, fullTxBytes, prefixBytes, prevTxnIdBytes, postFixBytes, baseCcs, basePk)
	end = time.Since(start)
	fmt.Printf("Base Case Prof took : %s\n", end)

	//can create a lightweight witness here for verification
	//err := native_plonk.Verify(genesisProof, verifyingKey, genesisWitness, plonk.GetNativeVerifierOptions(outerField, innerField))

	//outerField := ecc.BW6_761.ScalarField()
	innerWitness, err := groth16.ValueOfWitness[ScalarField](genesisWitness)
	innerProof, err := groth16.ValueOfProof[G1Affine, G2Affine](genesisProof)

	innerVk, err := groth16.ValueOfVerifyingKey[G1Affine, G2Affine, GTEl](baseVk)

	//spending tx info
	prefixBytes, _ = hex.DecodeString("0200000001")
	prevTxnIdBytes, _ = hex.DecodeString("faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71")
	postFixBytes, _ = hex.DecodeString("000000006a47304402200ce76e906d995091f28ca40f4579c358bce832cd0d5c5535e4736e4444f6ba2602204fa80867c48e6016b3fa013633ad87203a18487786d8758ee3fe8a6ad5efdf06412103f368e789ce7c6152cc3a36f9c68e69b93934ce0b8596f9cd8032061d5feff4fffeffffff020065cd1d000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac1e64cd1d000000001976a914ce3e1e6345551bed999b48ab8b2ebb1ca880bcda88ac70000000")
	fullTxBytes, _ = hex.DecodeString("0200000001faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71000000006a47304402200ce76e906d995091f28ca40f4579c358bce832cd0d5c5535e4736e4444f6ba2602204fa80867c48e6016b3fa013633ad87203a18487786d8758ee3fe8a6ad5efdf06412103f368e789ce7c6152cc3a36f9c68e69b93934ce0b8596f9cd8032061d5feff4fffeffffff020065cd1d000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac1e64cd1d000000001976a914ce3e1e6345551bed999b48ab8b2ebb1ca880bcda88ac70000000")

	outerAssignment := CreateOuterAssignment(innerWitness, innerProof, innerVk, prefixBytes, prevTxnIdBytes, postFixBytes, fullTxBytes)
	outerWitness, err := frontend.NewWitness(&outerAssignment, outerField)

	start = time.Now()
	outerCcs, outerProvingKey, outerVerifyingKey, err := SetupNormalCase(outerField, baseCcs, innerVk)
	end = time.Since(start)
	fmt.Printf("Normal case setup took : %s\n", end)
	assert.NoError(err)

	start = time.Now()
	outerProof, err := native_groth16.Prove(outerCcs, outerProvingKey, outerWitness, groth16.GetNativeProverOptions(outerField, innerField))
	end = time.Since(start)
	fmt.Printf("Normal case Proof took : %s\n", end)

	//verify the normal proof
	assert.NoError(err)
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

	innerField := ecc.BLS24_315.ScalarField()
	outerField := ecc.BW6_633.ScalarField()
	//innerField := ecc.BLS12_377.ScalarField()
	//outerField := ecc.BW6_761.ScalarField()

	//issuance txn
	fullTxGenesisBytes, _ := hex.DecodeString("020000000190bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")
	prefixGenesisBytes, _ := hex.DecodeString("0200000001")
	prevTxnIdGenesisBytes, _ := hex.DecodeString("90bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7")
	postFixGenesisBytes, _ := hex.DecodeString("000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")

	//innerCcs, innerVK, innerWitness, innerProof :=
	assert := test.NewAssert(t)
	baseCcs, basePk, baseVk, err := SetupBaseCase(innerField)
	innerWitness, innerProof, err := CreateBaseCaseProof(outerField, innerField, fullTxGenesisBytes, prefixGenesisBytes, prevTxnIdGenesisBytes, postFixGenesisBytes, baseCcs, basePk)
	if err != nil {
		panic(err)
	}

	circuitVk, err := groth16.ValueOfVerifyingKey[G1Affine, G2Affine, GTEl](baseVk)
	if err != nil {
		panic(err)
	}
	circuitWitness, err := groth16.ValueOfWitness[ScalarField](innerWitness)
	if err != nil {
		panic(err)
	}
	circuitProof, err := groth16.ValueOfProof[G1Affine, G2Affine](innerProof)
	if err != nil {
		panic(err)
	}

	outerCircuit := &Sha256Circuit[ScalarField, G1Affine, G2Affine, GTEl]{
		PreviousProof:   groth16.PlaceholderProof[G1Affine, G2Affine](baseCcs),
		PreviousVk:      circuitVk,
		PreviousWitness: groth16.PlaceholderWitness[ScalarField](baseCcs),
	}

	//spending transaction
	prefixBytes, _ := hex.DecodeString("0200000001")
	prevTxnIdBytes, _ := hex.DecodeString("faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71")
	postFixBytes, _ := hex.DecodeString("000000006a47304402200ce76e906d995091f28ca40f4579c358bce832cd0d5c5535e4736e4444f6ba2602204fa80867c48e6016b3fa013633ad87203a18487786d8758ee3fe8a6ad5efdf06412103f368e789ce7c6152cc3a36f9c68e69b93934ce0b8596f9cd8032061d5feff4fffeffffff020065cd1d000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac1e64cd1d000000001976a914ce3e1e6345551bed999b48ab8b2ebb1ca880bcda88ac70000000")

	fullTxBytes, _ := hex.DecodeString("0200000001faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71000000006a47304402200ce76e906d995091f28ca40f4579c358bce832cd0d5c5535e4736e4444f6ba2602204fa80867c48e6016b3fa013633ad87203a18487786d8758ee3fe8a6ad5efdf06412103f368e789ce7c6152cc3a36f9c68e69b93934ce0b8596f9cd8032061d5feff4fffeffffff020065cd1d000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac1e64cd1d000000001976a914ce3e1e6345551bed999b48ab8b2ebb1ca880bcda88ac70000000")

	outerAssignment := CreateOuterAssignment(circuitWitness, circuitProof, circuitVk, prefixBytes, prevTxnIdBytes, postFixBytes, fullTxBytes)

	err = test.IsSolved(outerCircuit, &outerAssignment, outerField)
	assert.NoError(err)

	//now follow-up with a first-spend and proof of the previous token

}
