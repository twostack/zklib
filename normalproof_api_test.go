package zklib

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark/test"
	txivc "github.com/twostack/zklib/twostack/groth16"
	"testing"
)

func TestComputeNormalProof(t *testing.T) {

	assert := test.NewAssert(t)

	bp, err := BootBaseProof(BASE_RAW_TX_SIZE)
	assert.NoError(err)

	fullTxBytes, _ := hex.DecodeString("020000000190bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")
	firstHash := sha256.Sum256(fullTxBytes)
	genesisTxId := sha256.Sum256(firstHash[:])

	genesisWitness, err := txivc.CreateBaseCaseFullWitness(fullTxBytes, genesisTxId[:])

	proof, err := bp.ComputeProof(genesisWitness)
	assert.NoError(err)

	//dump JSON proof to console
	jsonProof, err := json.Marshal(proof) //proof to bytes
	assert.NoError(err)
	fmt.Printf("Base Proof JSON: [%s]\n", string(jsonProof))

	publicBaseWitness, err := txivc.CreateBaseCaseLightWitness(genesisTxId[:], txivc.InnerCurve.ScalarField())
	//publicWitness, err := genesisWitness.Public()
	assert.NoError(err)

	isVerified := bp.VerifyProof(publicBaseWitness, proof)
	assert.True(isVerified)

	/***
	Base case complete.

	Start Normal Proof
	*/
	prefixBytes, _ := hex.DecodeString("0200000001")
	prevTxnIdBytes, _ := hex.DecodeString("faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71")
	postFixBytes, _ := hex.DecodeString("000000006a47304402200ce76e906d995091f28ca40f4579c358bce832cd0d5c5535e4736e4444f6ba2602204fa80867c48e6016b3fa013633ad87203a18487786d8758ee3fe8a6ad5efdf06412103f368e789ce7c6152cc3a36f9c68e69b93934ce0b8596f9cd8032061d5feff4fffeffffff020065cd1d000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac1e64cd1d000000001976a914ce3e1e6345551bed999b48ab8b2ebb1ca880bcda88ac70000000")
	fullTxBytes, _ = hex.DecodeString("0200000001faf3013aab53ae122e6cfdef7720c7a785fed4ce7f8f3dd19379f31e62651c71000000006a47304402200ce76e906d995091f28ca40f4579c358bce832cd0d5c5535e4736e4444f6ba2602204fa80867c48e6016b3fa013633ad87203a18487786d8758ee3fe8a6ad5efdf06412103f368e789ce7c6152cc3a36f9c68e69b93934ce0b8596f9cd8032061d5feff4fffeffffff020065cd1d000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac1e64cd1d000000001976a914ce3e1e6345551bed999b48ab8b2ebb1ca880bcda88ac70000000")
	firstHash = sha256.Sum256(fullTxBytes)
	currTxId := sha256.Sum256(firstHash[:])

	np, err := bootNormalProof(len(prefixBytes), len(postFixBytes), bp)
	assert.NoError(err)

	outerWitness, err := np.CreateFullWitness(publicBaseWitness, proof, bp.VerifyingKey, prefixBytes, prevTxnIdBytes, postFixBytes, currTxId[:])
	assert.NoError(err)

	outerProof, err := np.ComputeProof(*outerWitness)
	assert.NoError(err)

	//verify the normal proof
	outerPublicWitness, err := (*outerWitness).Public()
	assert.NoError(err)

	isOuterVerified := np.VerifyProof(outerPublicWitness, outerProof)

	assert.True(isOuterVerified)

}
