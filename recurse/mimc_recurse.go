/***
NOTICE : UNTESTED !!!!!
*/

package recurse

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	mimc2 "github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/emulated"
)

type MimcCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	CurrTxPrefix []frontend.Variable //5
	PrevTxId     []frontend.Variable
	CurrTxPost   []frontend.Variable //81

	//double-sha256 hash of the concatenation of above fields. Not reversed, so not quite a TxId
	CurrTxId []frontend.Variable `gnark:",public"` //probably needs to provide the reversed version to save circuit space
}

func (circuit *MimcCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {

	//reconstitute the transaction hex
	fullTx := append(circuit.CurrTxPrefix, circuit.PrevTxId...)
	fullTx = append(fullTx, circuit.CurrTxPost[:]...)

	//do double-sha256
	mimc, _ := mimc2.NewMiMC(api)
	mimc.Write(fullTx)

	//loop over the individual bytes of the calculated hash
	//and compare them to the expected digest
	api.AssertIsEqual(mimc.Sum(), circuit.CurrTxId)

	return nil
}
