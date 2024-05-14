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

	//working --> fullTxBytes, _ := hex.DecodeString("020000000190bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")
	fullTxBytes, _ := hex.DecodeString("0200000001f3d6a7e21461b45e5b11aea74395ea7fcfcc3e76c2e817471edb82b639ce15bd000000006a47304402207c4bb9164de089e2b42df060e5bf4eec57cf3676add2e4e4f63794c33d088d7d022022b02f0589001e8b67da1cd357ffedb30e483bb649a57b567c860523b1fb2181412102ab8dd48023ad7b25f56ab9ad7d5187e429db6acbe726150964bebbc634bd0fbfffffffff02c0868b3b000000001976a914d3be2df8108bef45d81247909673a81d1cf9e14c88ac40420f00000000001976a914d3be2df8108bef45d81247909673a81d1cf9e14c88ac00000000")

	start := time.Now()
	innerCcs, provingKey, verifyingKey, err := SetupBaseCase(len(fullTxBytes), ecc.BLS12_377.ScalarField())
	if err != nil {
		panic(err)
	}
	elapsed := time.Since(start)
	fmt.Printf("Setup took %s to complete \n", elapsed)

	firstHash := sha256.Sum256(fullTxBytes)
	genesisTxId := sha256.Sum256(firstHash[:])
	fmt.Printf("Proving with base TxId : [%s]\n", hex.EncodeToString(genesisTxId[:]))

	//fmt.Println(hex.EncodeToString(genesisTxId[:]))
	// create full genesis witness (placeholders, prevTxnIdBytes is empty
	//vk, err := plonk.ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](verifyingKey)
	genesisWitness, err := CreateBaseCaseFullWitness(fullTxBytes, genesisTxId[:])

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

	fullTxBytes, _ := hex.DecodeString("020000000190bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")

	start := time.Now()
	baseCcs, basePk, baseVk, err := SetupBaseCase(len(fullTxBytes), ecc.BLS12_377.ScalarField())
	end := time.Since(start)
	fmt.Printf("Setup Base Case took : %s\n", end)

	firstHash := sha256.Sum256(fullTxBytes)
	secondHash := sha256.Sum256(firstHash[:])

	genesisWitness, err := CreateBaseCaseFullWitness(fullTxBytes, secondHash[:])

	start = time.Now()
	genesisProof, err := native_groth16.Prove(baseCcs, basePk, genesisWitness, groth16.GetNativeProverOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
	end = time.Since(start)
	fmt.Printf("Base Case Proof took : %s\n", end)

	//can create a lightweight witness here for verification
	//err := native_plonk.Verify(genesisProof, verifyingKey, genesisWitness, plonk.GetNativeVerifierOptions(outerField, innerField))
	pubWitness, err := genesisWitness.Public()
	assert.NoError(err)

	err = native_groth16.Verify(genesisProof, baseVk, pubWitness, groth16.GetNativeVerifierOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
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

	outerWitness, err := frontend.NewWitness(&outerAssignment, ecc.BW6_761.ScalarField())

	start = time.Now()
	outerCcs, outerProvingKey, outerVerifyingKey, err := SetupNormalCase(len(prefixBytes), len(postFixBytes), ecc.BW6_761.ScalarField(), baseCcs)
	assert.NoError(err)
	end = time.Since(start)
	fmt.Printf("Normal case setup took : %s\n", end)

	start = time.Now()
	outerProof, err := native_groth16.Prove(outerCcs, outerProvingKey, outerWitness, groth16.GetNativeProverOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
	assert.NoError(err)
	end = time.Since(start)
	fmt.Printf("Normal case Proof took : %s\n", end)

	//verify the normal proof
	start = time.Now()
	publicWitness, err := outerWitness.Public()
	assert.NoError(err)
	err = native_groth16.Verify(outerProof, outerVerifyingKey, publicWitness, groth16.GetNativeVerifierOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
	assert.NoError(err)

	end = time.Since(start)
	fmt.Printf("Normal case verification took : %s\n", end)

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

	genesisWitness, err := CreateBaseCaseFullWitness(fullTxGenesisBytes, genesisTxId[:])

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

func TestNormalToNormalProof(t *testing.T) {
	//txnId := "3d295a8db832537a0f4963a1382833058f686060d8225bcff749d23c6129be96"
	//proof := "{\"Ar\":{\"X\":\"142352325045502335026558859355935440996724661250261332323054210955338910949061370103074890023322929408802373971431862391829523468795324483160672409753437650902312240937425452654409932529049911624224395139831892404917583359306594\",\"Y\":\"2086920927289928705135455697394221059933128722312818393665592893155860827225932342098054156073616290994057935472451526234254455389966976908075488546072898635190812609297827805967487169909445762719636472091526942701781684434004034\"},\"Krs\":{\"X\":\"5495937959100014930689652469403499136802821474195206299605722066562641794127318187155357025084172985598391534893986009963923702363291296570241873215975981676757001713838577787963138472814093655271320046805409196335578993284113448\",\"Y\":\"244752904235114433204177317599098738318934497122187777027034884795761120256680567631175388713967277251489046492050270311339238678690779214534466880136906548219074337791231436951575284083484844124236123919863437757589816593460397\"},\"Bs\":{\"X\":\"3455142531802966319291767540876000235580407901096794109341097372830692019787008380948605762376536520349496439312695788538466060368519007164914999511675506469742188822904904920507298585356775031230712861692221506248623785823727713\",\"Y\":\"1811932821520657952211752515122002154274722223070313932921403124020417660142281960465660325924108362037124219349946387927886871888182441604715204508371965855508577419333965783072035915375015472584841613791761551189314184440863146\"},\"Commitments\":[{\"X\":\"578745887598482032615271837639399987278856084770883659089555551408681192622780777690540047571800324588016479611221315116671217650912443297008429828265820042592070312402471698400292913714604060428157973329671026255165939496602227\",\"Y\":\"6570523218933512564511147643202337072025341103159465458606603129587111792353728837880269130588264525247614328003705167613329749049132032601833370734724003863099551715954914560672940106339959803426107590500016066629772386815744478\"}],\"CommitmentPok\":{\"X\":\"5991421863592132108312640594584698179941145411155193538948395993172751007539064216411042641373741704299954958246032862286077094079130523511373952854158769618238868051900664966871537980487934098038670834522380317113809577904557375\",\"Y\":\"2823589746205822814603914003715247034392571463650283582390613552394000250707326672591881224491993173281652113366222787827542413296316934278866903063181919110123962551463013637526982919946533074634735567317079205808167370747145424\"}}"

}
