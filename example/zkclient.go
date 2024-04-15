package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/std/recursion/plonk"
	"runtime"
	"time"
	"zklib"
	grothivc "zklib/twostack/groth16"
	plonkivc "zklib/twostack/plonk"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	start := time.Now()
	//benchNormalCasePlonk()
	benchNormalCaseGroth16()
	//benchLibApiBase()
	//benchLibApiNormal()
	end := time.Since(start)

	fmt.Printf("It took : %s", end)
}

func benchLibApiIssuance() {
	//bootstrap proof system

	//load proving keys

	//generate an issuance proof for a txn

	//serialize the proof to disk
}

func benchLibApiProofVerify() {
	//bootstrap proof system

	//load verifying key

	//load proof from disk

	//create witness data for proof

	//verify that proof holds for given witness
}

func benchLibApiNormal() {
	baseProof, _ := zklib.NewBaseProof()
	baseProof.ReadKeys()

	normalProof, err := zklib.NewNormalProof(baseProof.Ccs, baseProof.VerifyingKey)

	start := time.Now()
	err = normalProof.SetupKeys()
	if err != nil {
		fmt.Printf("Normal proof key setup failed %s\n")
		return
	}
	elapsed := time.Since(start)
	fmt.Printf("Setup took %s\n", elapsed)

	//write keys to disk

	start = time.Now()
	err = normalProof.WriteKeys()
	if err != nil {
		fmt.Printf("Exporting normal proof keys failed %s\n")
		return
	}
	elapsed = time.Since(start)
	fmt.Printf("Writing keys took: %s\n", elapsed)

	start = time.Now()
	err = normalProof.ReadKeys()
	if err != nil {
		fmt.Printf("Importing normal case keys failed %s\n")
		return
	}
	elapsed = time.Since(start)
	fmt.Printf("Reading back keys took: %s\n", elapsed)

}

func benchLibApiBase() {
	baseProof, err := zklib.NewBaseProof()

	if err != nil {
		fmt.Printf("failed to create proof object %s\n")
		return
	}

	start := time.Now()
	err = baseProof.SetupKeys()
	if err != nil {
		fmt.Printf("Base proof key setup failed %s\n")
		return
	}
	elapsed := time.Since(start)
	fmt.Printf("Setup took %s\n", elapsed)

	//write keys to disk

	start = time.Now()
	baseProof.WriteKeys()
	elapsed = time.Since(start)
	fmt.Printf("Writing keys took: %s\n", elapsed)

	start = time.Now()
	baseProof.ReadKeys()
	elapsed = time.Since(start)
	fmt.Printf("Reading back keys took: %s\n", elapsed)

	//test recovery from disk
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
	genesisProof, err := grothivc.ComputeProof(innerCcs, provingKey, genesisWitness, proverOptions)
	elapsed = time.Since(start)
	fmt.Printf("Base case proof created: %s\n", elapsed)

	if err != nil {
		fmt.Printf("Fail on base case proof ! %s\n", err)
		return
	}

	verifierOptions := groth16.GetNativeVerifierOptions(outerField, innerField)
	isVerified := grothivc.VerifyProof(genesisWitness, genesisProof, verifyingKey, verifierOptions)
	if !isVerified {
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
		fmt.Printf("Fail ! %s\n", err)
		return
	}

	start = time.Now()
	outerProof, err := grothivc.ComputeProof(outerCcs, outerProvingKey, outerWitness, proverOptions)
	elapsed = time.Since(start)
	fmt.Printf("Proof compute took : %s\n", elapsed)
	if err != nil {
		fmt.Printf("Proof computation failed ! %s\n", err)
		return
	}

	//verify the normal proof
	publicOuterWitness, err := outerWitness.Public()
	isVerified = grothivc.VerifyProof(publicOuterWitness, outerProof, outerVerifyingKey, verifierOptions)
	if !isVerified {
		return
	}
}
