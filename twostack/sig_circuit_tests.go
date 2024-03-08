package twostack

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test"
	"testing"
)

func TestBaseCase(t *testing.T) {

	assert := test.NewAssert(t)
	innerField := ecc.BLS12_377.ScalarField()

	baseCcs, basePk, baseVk, err := SetupBaseCase(innerField)
	if err != nil {
		panic(err)
	}

	fullTxBytes, _ := hex.DecodeString("020000000190bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")

	firstHash := sha256.Sum256(fullTxBytes)
	txId := sha256.Sum256(firstHash[:])

	genesisWitness, genesisProof, err := CreateBaseCaseProof(fullTxBytes, txId, baseCcs, basePk)

	circuitVk, err := plonk.ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](baseVk)
	if err != nil {
		panic(err)
	}
	circuitWitness, err := plonk.ValueOfWitness[sw_bls12377.ScalarField](genesisWitness)
	if err != nil {
		panic(err)
	}
	circuitProof, err := plonk.ValueOfProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](genesisProof)
	if err != nil {
		panic(err)
	}

	outerCircuit := &SigCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		PreviousProof:   plonk.PlaceholderProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](baseCcs),
		PreviousVk:      circuitVk,
		PreviousWitness: plonk.PlaceholderWitness[sw_bls12377.ScalarField](baseCcs),
	}

	//spending transaction

	outerAssignment := CreateOuterAssignment(circuitWitness, circuitProof, circuitVk, fullTxBytes, txId)

	err = test.IsSolved(outerCircuit, &outerAssignment, ecc.BW6_761.ScalarField())
	assert.NoError(err)

}
