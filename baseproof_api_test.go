package zklib

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	native_groth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/test"
	txivc "github.com/twostack/zklib/twostack/groth16"
	"testing"
)

func TestComputeProof(t *testing.T) {

	assert := test.NewAssert(t)

	bp, err := BootBaseProof(BASE_RAW_TX_SIZE)
	assert.NoError(err)

	fullTxBytes, _ := hex.DecodeString("020000000190bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")
	firstHash := sha256.Sum256(fullTxBytes)
	genesisTxId := sha256.Sum256(firstHash[:])

	genesisWitness, err := txivc.CreateBaseCaseFullWitness(fullTxBytes, genesisTxId)

	proof, err := bp.ComputeProof(genesisWitness)
	assert.NoError(err)

	//dump JSON proof to console
	jsonProof, err := json.Marshal(proof) //proof to bytes
	assert.NoError(err)
	fmt.Printf("Base Proof JSON: [%s]\n", string(jsonProof))

	publicWitness, err := txivc.CreateBaseCaseLightWitness(genesisTxId[:], txivc.InnerCurve.ScalarField())
	//publicWitness, err := genesisWitness.Public()
	assert.NoError(err)

	isVerified := bp.VerifyProof(publicWitness, &proof)
	assert.True(isVerified)

}

func TestVerifyJsonProof(t *testing.T) {

	assert := test.NewAssert(t)

	bp, err := BootBaseProof(BASE_RAW_TX_SIZE)
	assert.NoError(err)

	fullTxBytes, _ := hex.DecodeString("020000000190bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")
	firstHash := sha256.Sum256(fullTxBytes)
	genesisTxId := sha256.Sum256(firstHash[:])

	txProof := native_groth16.NewProof(txivc.InnerCurve)

	//var innerProofBytes = []byte(normalInfo.Proof)
	jsonProof := "{\"Ar\":{\"X\":\"33036028380428168970435360603885224677657776312810493917852995805500426976727072507344310043288\",\"Y\":\"36266896970900178392046370722388138897904686351854717507878870981152168978508993938382363176772\"},\"Krs\":{\"X\":\"11250522036893253512065907418935505810363524991740231582017990704070435381515177971454624739940\",\"Y\":\"11171161845744339591876141292153285428820190835715061577850271568940239117514630686549874702471\"},\"Bs\":{\"X\":{\"B0\":{\"A0\":\"5402271866678279963760608113001902219913920644474018490634383994728571252618400264937796093004\",\"A1\":\"4366724457621301949987664988650107441875845921582350962682516333920134464897665390774198793024\"},\"B1\":{\"A0\":\"36654000062392144929663742623874962596669540454280280322604446972987177552192822935833950765322\",\"A1\":\"10504605873626462041602812061352195470068642292425491770901732658719559681491356015233879652424\"}},\"Y\":{\"B0\":{\"A0\":\"13051873758401600118398116500019667727380995688684985350093483796904191040992284556692126983236\",\"A1\":\"28796224188271897652955603145661025852609598257879081673418098891519864284019844434992952819234\"},\"B1\":{\"A0\":\"17239487636991811243666052732625482071493498391117449720126694475509842511617018342201339079221\",\"A1\":\"14970455863316306454939688254946336588327178087457091587120070743901319235385812006457118926082\"}}},\"Commitments\":[{\"X\":\"15699005025412594288127118587709600287784895879379127011299508169356059184274552865536916661252\",\"Y\":\"35407567240950262238253738824476440907562729028069167118259342769585057710583812325752435195878\"}],\"CommitmentPok\":{\"X\":\"31506825269902125185352125875651824595005601570445548779714051989581390376536908130833446623340\",\"Y\":\"18426126989615339265310346141007595764553013739674476181403156916258357999749115146872850388933\"}}"
	err = json.Unmarshal([]byte(jsonProof), &txProof)
	assert.NoError(err)

	publicWitness, err := txivc.CreateBaseCaseLightWitness(genesisTxId[:], txivc.InnerCurve.ScalarField())
	assert.NoError(err)

	isVerified := bp.VerifyProof(publicWitness, &txProof)
	assert.True(isVerified)

}

func TestProveAndVerifySplitSystems(t *testing.T) {

	assert := test.NewAssert(t)

	bp, err := BootBaseProof(BASE_RAW_TX_SIZE)
	assert.NoError(err)

	fullTxBytes, _ := hex.DecodeString("020000000190bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")
	firstHash := sha256.Sum256(fullTxBytes)
	genesisTxId := sha256.Sum256(firstHash[:])

	genesisWitness, err := txivc.CreateBaseCaseFullWitness(fullTxBytes, genesisTxId)

	proof, err := bp.ComputeProof(genesisWitness)
	assert.NoError(err)

	//dump JSON proof to console
	jsonProof, err := json.Marshal(proof) //proof to bytes
	assert.NoError(err)
	fmt.Printf("Base Proof JSON: [%s]\n", string(jsonProof))

	//boot second proof system from file on disk, and verify in there
	bp2, err := BootBaseProof(BASE_RAW_TX_SIZE)
	assert.NoError(err)

	publicWitness, err := txivc.CreateBaseCaseLightWitness(genesisTxId[:], txivc.InnerCurve.ScalarField())
	//publicWitness, err := genesisWitness.Public()
	assert.NoError(err)

	isVerified := bp2.VerifyProof(publicWitness, &proof)
	assert.True(isVerified)

}

func TestProofSystemEquality(t *testing.T) {

	assert := test.NewAssert(t)

	bp, err := BootBaseProof(BASE_RAW_TX_SIZE)
	assert.NoError(err)
	bp2, err := BootBaseProof(BASE_RAW_TX_SIZE)
	assert.NoError(err)

	//test for equality after ser/deser
	var bp1VkBuf bytes.Buffer
	var bp2VkBuf bytes.Buffer
	(*bp.VerifyingKey).WriteRawTo(&bp1VkBuf)
	(*bp2.VerifyingKey).WriteRawTo(&bp2VkBuf)

	assert.True(bytes.Equal(bp1VkBuf.Bytes(), bp2VkBuf.Bytes()))

	//test for equality after ser/deser
	var bp1PkBuf bytes.Buffer
	var bp2PkBuf bytes.Buffer
	(*bp.VerifyingKey).WriteRawTo(&bp1PkBuf)
	(*bp2.VerifyingKey).WriteRawTo(&bp2PkBuf)

	assert.True(bytes.Equal(bp1PkBuf.Bytes(), bp2PkBuf.Bytes()))
}
