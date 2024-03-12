package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	native_groth16 "github.com/consensys/gnark/backend/groth16"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/std/recursion/plonk"
	"time"
	"zklib"
	grothivc "zklib/twostack/groth16"
	plonkivc "zklib/twostack/plonk"
)

func main() {
	start := time.Now()
	//zklib.GenerateCircuitParams()
	//zklib.UnmarshalCircuitParams()
	//testCreateAndVerify()
	//benchNormalCasePlonk()
	benchNormalCaseGroth16()
	end := time.Since(start)

	fmt.Printf("It took : %s", end)
}

func testCreateAndVerify() {

	start := time.Now()
	prefixBytes, _ := hex.DecodeString("0200000001")
	prevTxnIdBytes, _ := hex.DecodeString("ae4b7f1769154bb04e9c666a4dbb31eb2ec0c4e01d965cbb1ca4574e7ed40a19")
	postFixBytes, _ := hex.DecodeString("000000004847304402200e993f6bc2319615b662ac7f5882bc78dc35101d1b110a0edf2fd79dea2206c2022017e352e87390227a39b7eae6510cdff9e1cedc8a517e811b90ac6b6fdc8d7d0441feffffff0200ca9a3b000000001976a914783b608b9278a187641d047c14dbf63e1be5bc8888ac00196bee000000001976a9142bfccc428186e69fc94fde6d7396f19482dd5a7988ac65000000")
	fullTxBytes, _ := hex.DecodeString("0200000001ae4b7f1769154bb04e9c666a4dbb31eb2ec0c4e01d965cbb1ca4574e7ed40a19000000004847304402200e993f6bc2319615b662ac7f5882bc78dc35101d1b110a0edf2fd79dea2206c2022017e352e87390227a39b7eae6510cdff9e1cedc8a517e811b90ac6b6fdc8d7d0441feffffff0200ca9a3b000000001976a914783b608b9278a187641d047c14dbf63e1be5bc8888ac00196bee000000001976a9142bfccc428186e69fc94fde6d7396f19482dd5a7988ac65000000")

	firstHash := sha256.Sum256(fullTxBytes)
	currTxId := sha256.Sum256(firstHash[:])

	innerWitness, err := zklib.CreateInnerWitness(prefixBytes, prevTxnIdBytes, postFixBytes, currTxId[:])
	if err != nil {
		fmt.Println(err)
		return
	}
	end := time.Since(start)
	fmt.Printf("Inner witness assembled : %s\n", end)

	start = time.Now()
	innerCcs, err := zklib.CompileInnerCiruit()

	if err != nil {
		fmt.Println(err)
		return
	}
	end = time.Since(start)
	fmt.Printf("Circuit compiled : %s\n", end)

	start = time.Now()

	innerVK, innerPK, err := zklib.SetupCircuit(innerCcs)
	if err != nil {
		fmt.Println(err)
		return
	}
	end = time.Since(start)
	fmt.Printf("Circuit Setup: %s\n", end)

	start = time.Now()

	innerProof, err := zklib.GenerateInnerProof(innerWitness, innerCcs, innerPK)
	if err != nil {
		fmt.Println(err)
		return
	}
	end = time.Since(start)
	fmt.Printf("Generated Inner PreviousProof: %s\n", end)

	start = time.Now()

	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		fmt.Println(err)
		return
	}

	var isValid = zklib.VerifyInnerProof(innerPubWitness, innerProof, innerVK)

	if isValid == false {
		fmt.Println("PreviousProof Failed !")
	}

	end = time.Since(start)
	fmt.Printf("Verified Inner PreviousProof: %s\n", end)

}

func benchNormalCasePlonk() {

	innerField := ecc.BLS12_377.ScalarField()
	//outerField := ecc.BLS12_377.ScalarField()
	outerField := ecc.BW6_761.ScalarField()

	fullTxBytes, _ := hex.DecodeString("020000000190bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")
	prefixBytes, _ := hex.DecodeString("0200000001")
	prevTxnIdBytes, _ := hex.DecodeString("90bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7")
	postFixBytes, _ := hex.DecodeString("000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")

	//setup circuit params
	start := time.Now()
	innerCcs, provingKey, verifyingKey, err := plonkivc.SetupBaseCase(innerField)
	elapsed := time.Since(start)
	fmt.Printf("Base case setup: %s\n", elapsed)

	start = time.Now()
	innerVk, err := plonk.ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](verifyingKey)
	outerCcs, outerProvingKey, outerVerifyingKey, err := plonkivc.SetupNormalCase(outerField, innerCcs, innerVk) //using placeholders for pk and proof
	elapsed = time.Since(start)
	fmt.Printf("Normal Case Setup: %s\n", elapsed)
	if err != nil {
		fmt.Printf("Fail ! %s", err)
		return
	}

	if err != nil {
		fmt.Printf("Fail ! %s", err)
		return
	}
	start = time.Now()
	genesisWitness, genesisProof, err := plonkivc.CreateBaseCaseProof(fullTxBytes, prefixBytes, prevTxnIdBytes, postFixBytes, innerCcs, provingKey)
	elapsed = time.Since(start)
	fmt.Printf("Base case proof created: %s\n", elapsed)

	if err != nil {
		fmt.Printf("Fail ! %s", err)
		return
	}
	//can create a lightweight witness here for verification
	//err := native_plonk.Verify(genesisProof, verifyingKey, genesisWitness, plonk.GetNativeVerifierOptions(outerField, innerField))

	//outerField := ecc.BW6_761.ScalarField()
	innerWitness, err := plonk.ValueOfWitness[sw_bls12377.ScalarField](genesisWitness)
	innerProof, err := plonk.ValueOfProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](genesisProof)

	//spending tx info
	prefixBytes, _ = hex.DecodeString("0200000001")
	prevTxnIdBytes, _ = hex.DecodeString("faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71")
	postFixBytes, _ = hex.DecodeString("000000006a47304402200ce76e906d995091f28ca40f4579c358bce832cd0d5c5535e4736e4444f6ba2602204fa80867c48e6016b3fa013633ad87203a18487786d8758ee3fe8a6ad5efdf06412103f368e789ce7c6152cc3a36f9c68e69b93934ce0b8596f9cd8032061d5feff4fffeffffff020065cd1d000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac1e64cd1d000000001976a914ce3e1e6345551bed999b48ab8b2ebb1ca880bcda88ac70000000")
	fullTxBytes, _ = hex.DecodeString("0200000001faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71000000006a47304402200ce76e906d995091f28ca40f4579c358bce832cd0d5c5535e4736e4444f6ba2602204fa80867c48e6016b3fa013633ad87203a18487786d8758ee3fe8a6ad5efdf06412103f368e789ce7c6152cc3a36f9c68e69b93934ce0b8596f9cd8032061d5feff4fffeffffff020065cd1d000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac1e64cd1d000000001976a914ce3e1e6345551bed999b48ab8b2ebb1ca880bcda88ac70000000")

	outerAssignment := plonkivc.CreateOuterAssignment(innerWitness, innerProof, innerVk, prefixBytes, prevTxnIdBytes, postFixBytes, fullTxBytes)
	outerWitness, err := frontend.NewWitness(&outerAssignment, outerField)
	if err != nil {
		fmt.Printf("Fail ! %s", err)
		return
	}

	start = time.Now()
	outerProof, err := native_plonk.Prove(outerCcs, outerProvingKey, outerWitness, plonk.GetNativeProverOptions(outerField, innerField))
	elapsed = time.Since(start)
	fmt.Printf("Normal case proof created: %s\n", elapsed)
	if err != nil {
		fmt.Printf("Fail ! %s", err)
		return
	}

	//verify the normal proof
	publicWitness, err := outerWitness.Public()
	err = native_plonk.Verify(outerProof, outerVerifyingKey, publicWitness, plonk.GetNativeVerifierOptions(outerField, innerField))

	if err != nil {
		fmt.Printf("Fail ! %s", err)
		return
	}
}

func benchNormalCaseGroth16() {

	innerField := ecc.BLS24_315.ScalarField()
	outerField := ecc.BW6_633.ScalarField()

	proverOptions := groth16.GetNativeProverOptions(outerField, innerField)

	fullTxBytes, _ := hex.DecodeString("020000000190bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")
	prefixBytes, _ := hex.DecodeString("0200000001")
	prevTxnIdBytes, _ := hex.DecodeString("90bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7")
	postFixBytes, _ := hex.DecodeString("000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")

	//setup circuit params
	start := time.Now()
	innerCcs, provingKey, verifyingKey, err := grothivc.SetupBaseCase(innerField)
	elapsed := time.Since(start)
	fmt.Printf("Base case setup: %s\n", elapsed)

	firstHash := sha256.Sum256(fullTxBytes)
	genesisTxId := sha256.Sum256(firstHash[:])

	genesisWitness, err := grothivc.CreateBaseCaseWitness(prefixBytes, postFixBytes, prevTxnIdBytes, genesisTxId, innerField)

	start = time.Now()
	genesisProof, err := grothivc.CreateBaseCaseProof(proverOptions, innerCcs, genesisWitness, provingKey)
	elapsed = time.Since(start)
	fmt.Printf("Base case proof created: %s\n", elapsed)

	if err != nil {
		fmt.Printf("Fail on base case proof ! %s\n", err)
		return
	}

	publicWitness, err := genesisWitness.Public()
	err = native_groth16.Verify(genesisProof, verifyingKey, publicWitness, groth16.GetNativeVerifierOptions(outerField, innerField))
	if err != nil {
		fmt.Printf("Fail on base case verification! %s\n", err)
		return
	}

	//can create a lightweight witness here for verification
	innerWitness, err := groth16.ValueOfWitness[grothivc.ScalarField](genesisWitness)
	innerProof, err := groth16.ValueOfProof[grothivc.G1Affine, grothivc.G2Affine](genesisProof)
	innerVk, err := groth16.ValueOfVerifyingKey[grothivc.G1Affine, grothivc.G2Affine, grothivc.GTEl](verifyingKey)

	start = time.Now()
	outerCcs, outerProvingKey, outerVerifyingKey, err := grothivc.SetupNormalCase(outerField, innerCcs, innerVk) //using placeholders for pk and proof
	elapsed = time.Since(start)
	fmt.Printf("Normal Case Setup: %s\n", elapsed)
	if err != nil {
		fmt.Printf("Fail on normal case setup! %s\n", err)
		return
	}

	//spending tx info
	prefixBytes, _ = hex.DecodeString("0200000001")
	prevTxnIdBytes, _ = hex.DecodeString("faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71")
	postFixBytes, _ = hex.DecodeString("000000006a47304402200ce76e906d995091f28ca40f4579c358bce832cd0d5c5535e4736e4444f6ba2602204fa80867c48e6016b3fa013633ad87203a18487786d8758ee3fe8a6ad5efdf06412103f368e789ce7c6152cc3a36f9c68e69b93934ce0b8596f9cd8032061d5feff4fffeffffff020065cd1d000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac1e64cd1d000000001976a914ce3e1e6345551bed999b48ab8b2ebb1ca880bcda88ac70000000")
	fullTxBytes, _ = hex.DecodeString("0200000001faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71000000006a47304402200ce76e906d995091f28ca40f4579c358bce832cd0d5c5535e4736e4444f6ba2602204fa80867c48e6016b3fa013633ad87203a18487786d8758ee3fe8a6ad5efdf06412103f368e789ce7c6152cc3a36f9c68e69b93934ce0b8596f9cd8032061d5feff4fffeffffff020065cd1d000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac1e64cd1d000000001976a914ce3e1e6345551bed999b48ab8b2ebb1ca880bcda88ac70000000")

	outerAssignment := grothivc.CreateOuterAssignment(innerWitness, innerProof, innerVk, prefixBytes, prevTxnIdBytes, postFixBytes, fullTxBytes)
	outerWitness, err := frontend.NewWitness(&outerAssignment, outerField)
	if err != nil {
		fmt.Printf("Fail ! %s", err)
		return
	}

	start = time.Now()
	outerProof, err := native_groth16.Prove(outerCcs, outerProvingKey, outerWitness, proverOptions)
	elapsed = time.Since(start)
	fmt.Printf("Normal case proof created: %s\n", elapsed)
	if err != nil {
		fmt.Printf("Fail ! %s", err)
		return
	}

	//verify the normal proof
	publicOuterWitness, err := outerWitness.Public()
	err = native_groth16.Verify(outerProof, outerVerifyingKey, publicOuterWitness, groth16.GetNativeVerifierOptions(outerField, innerField))

	if err != nil {
		fmt.Printf("Fail ! %s", err)
		return
	}
}
