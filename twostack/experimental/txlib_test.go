package experimental

import (
	"encoding/hex"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"testing"
)

func TestInnerProofCircuit(t *testing.T) {

	fullTxBytes, _ := hex.DecodeString("020000000190bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000")

	witness := TxCircuit{
		TxPreImage: uints.NewU8Array(fullTxBytes),
	}

	testCircuit := &TxCircuit{
		TxPreImage: uints.NewU8Array(fullTxBytes),
	}

	err := test.IsSolved(testCircuit, &witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}

	assert := test.NewAssert(t)

	assert.ProverSucceeded(testCircuit, &TxCircuit{
		TxPreImage: uints.NewU8Array(fullTxBytes),
		//Hash: witness.Hash,
	}, test.WithCurves(ecc.BN254))
}
