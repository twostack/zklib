package experimental

import (
	"github.com/consensys/gnark-crypto/ecc"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
	"math/big"
)

type TxCircuit struct {
	TxPreImage []uints.U8 `gnark:",public"` //probably needs to provide the reversed version to save circuit space
}

/*
 static function readOutput(bytes tx, int outputIndex): Output {
    // first 4 bytes version
    // 1 byte input num, only support max 3
    int pos = 4;
    int ninputs = Utils.fromLEUnsigned(tx[pos: pos + 1]);
    pos = pos + 1;
    bytes res = b'';
    int satoshis = 0;
    // max support 3 input
    // input
    require(ninputs <= 3);
    loop(3): i {
      if (i < ninputs) {
        // output point 36 bytes
        pos = pos + 36;
        // 1 byte var
        // script code + 4 bytes sequence
        int varLen = Utils.fromLEUnsigned(tx[pos: pos + 1]);
        if (varLen < 253) {
          int scriptLen = varLen;
          pos = pos + 1 + scriptLen + 4;
        } else if (varLen == 253) {
          int scriptLen = Utils.fromLEUnsigned(tx[pos + 1: pos + 3]);
          pos = pos + 3 + scriptLen + 4;
        } else if (varLen == 254) {
          int scriptLen = Utils.fromLEUnsigned(tx[pos + 1: pos + 5]);
          pos = pos + 5 + scriptLen + 4;
        } else {
          int scriptLen = Utils.fromLEUnsigned(tx[pos + 1: pos + 9]);
          pos = pos + 9 + scriptLen + 4;
        }
      }
    }
*/

type VarInt struct {
	value big.Int
}

func ByteVal(u8 uints.U8) int {
	return 0
}

//func (vi *VarInt) New(u8Val uints.U8) big.Int{
//
//   vi.value = u8Val
//}

type TxOutput struct {
	satoshis     big.Int
	scriptPubKey []uints.U8
}

type TxInput struct {
}

//func readUint32(bytes []uints.U8) int {
//	return (bytes[0] & 0xff) |
//		((bytes[1] & 0xff) << 8) |
//		((bytes[2] & 0xff) << 16) |
//		((bytes[3] & 0xff) << 24)
//}

func (circuit *TxCircuit) parseTx(api frontend.API, tx []uints.U8, ndx int) (*TxOutput, error) {

	//uapi, _ := uints.New[uints.U32](api)
	//txLen := len(tx)
	//txPos := 0
	//version
	// first 4 bytes version (readUint32)
	//version := tx[:4]
	//fr.BigEndian.Element(version)

	//field, err := emulated.NewField[FR](api)

	//witnessTokenIdBits := field.ToBits(version[0].Val)
	//witnessTokenId := bits.FromBinary(api, witnessTokenIdBits)
	//uapi.ByteAssertEq(circuit.TokenId[i], uapi.ByteValueOf(witnessTokenId))

	//uapi.ByteAssertEq('200001', version) //version 2 transactions only

	// 1 byte input num, only support max 3
	//int pos = 4;
	//int ninputs = Utils.fromLEUnsigned(tx[pos: pos + 1]);
	nInputByte := tx[4:5]
	ByteVal(nInputByte[0])

	//inputs

	//outputs

	//locktime

	return nil, nil
}

func (circuit *TxCircuit) Define(api frontend.API) error {

	//fr.NewElement()
	circuit.parseTx(api, circuit.TxPreImage, 0)

	//for i := range circuit.TxPreImage {
	//	uapi.ByteAssertEq(circuit.TokenId[i], circuit.CurrTxId[i])
	//	uapi.ByteValueOf()
	//}
	return nil
}

func SetupTxLib(innerField *big.Int) (constraint.ConstraintSystem, native_plonk.ProvingKey, native_plonk.VerifyingKey, error) {

	baseCcs, err := frontend.Compile(innerField, scs.NewBuilder,
		&SigCircuitBaseCase[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{})

	if err != nil {
		return nil, nil, nil, err
	}

	srs, srsLagrange, err := unsafekzg.NewSRS(baseCcs)

	if err != nil {
		return nil, nil, nil, err
	}

	innerPK, innerVK, err := native_plonk.Setup(baseCcs, srs, srsLagrange)
	if err != nil {
		return nil, nil, nil, err
	}
	return baseCcs, innerPK, innerVK, nil
}

func CreateTxProof(fullTxBytes []byte, innerCcs constraint.ConstraintSystem, provingKey native_plonk.ProvingKey) (
	witness.Witness,
	native_plonk.Proof,
	error,
) {

	innerField := ecc.BLS12_377.ScalarField()
	outerField := ecc.BW6_761.ScalarField()

	genesisWitness, err := CreateTxWitness(fullTxBytes)
	if err != nil {
		return nil, nil, err
	}

	proof, err := native_plonk.Prove(innerCcs, provingKey, genesisWitness, plonk.GetNativeProverOptions(outerField, innerField))

	return genesisWitness, proof, err
}

func CreateTxWitness(
	fullTxBytes []byte,
) (witness.Witness, error) {

	innerAssignment := TxCircuit{}

	//assign the current Txn data
	copy(innerAssignment.TxPreImage[:], uints.NewU8Array(fullTxBytes))

	innerWitness, err := frontend.NewWitness(&innerAssignment, ecc.BLS12_377.ScalarField())
	if err != nil {
		return nil, err
	}
	return innerWitness, nil
}
