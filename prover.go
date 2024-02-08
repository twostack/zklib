package zklib

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
	"log"
	"os"
	"time"
	"zklib/recurse"
)

func compileInnerCiruit() (constraint.ConstraintSystem, error) {
	innerField := ecc.BLS12_377.ScalarField()
	innerCcs, err := frontend.Compile(innerField, scs.NewBuilder, &recurse.Sha256InnerCircuit{})
	if err != nil {
		return nil, err
	}

	return innerCcs, nil
}

func SetupInnerProof() (constraint.ConstraintSystem, native_plonk.VerifyingKey, native_plonk.ProvingKey, error) {

	innerCcs, err := compileInnerCiruit()

	if err != nil {
		panic(err)
	}

	srs, srsLagrange, err := unsafekzg.NewSRS(innerCcs)

	if err != nil {
		panic(err)
	}

	innerPK, innerVK, err := native_plonk.Setup(innerCcs, srs, srsLagrange)
	if err != nil {
		return nil, nil, nil, err
	}

	return innerCcs, innerVK, innerPK, nil

}

func CreateInnerWitness(prefixBytes []byte, prevTxnIdBytes []byte, postfixBytes []byte) (witness.Witness, error) {
	innerField := ecc.BLS12_377.ScalarField()

	//prefixBytes, _ := hex.DecodeString("0200000001")
	//prevTxnIdBytes, _ := hex.DecodeString("ae4b7f1769154bb04e9c666a4dbb31eb2ec0c4e01d965cbb1ca4574e7ed40a19")
	//postFixBytes, _ := hex.DecodeString("000000004847304402200e993f6bc2319615b662ac7f5882bc78dc35101d1b110a0edf2fd79dea2206c2022017e352e87390227a39b7eae6510cdff9e1cedc8a517e811b90ac6b6fdc8d7d0441feffffff0200ca9a3b000000001976a914783b608b9278a187641d047c14dbf63e1be5bc8888ac00196bee000000001976a9142bfccc428186e69fc94fde6d7396f19482dd5a7988ac65000000")

	fullTxBytes, _ := hex.DecodeString("0200000001ae4b7f1769154bb04e9c666a4dbb31eb2ec0c4e01d965cbb1ca4574e7ed40a19000000004847304402200e993f6bc2319615b662ac7f5882bc78dc35101d1b110a0edf2fd79dea2206c2022017e352e87390227a39b7eae6510cdff9e1cedc8a517e811b90ac6b6fdc8d7d0441feffffff0200ca9a3b000000001976a914783b608b9278a187641d047c14dbf63e1be5bc8888ac00196bee000000001976a9142bfccc428186e69fc94fde6d7396f19482dd5a7988ac65000000")

	firstHash := sha256.Sum256(fullTxBytes)
	currTxId := sha256.Sum256(firstHash[:])

	fmt.Println(hex.EncodeToString(currTxId[:]))
	// inner proof
	innerAssignment := &recurse.Sha256InnerCircuit{}

	copy(innerAssignment.CurrTxPrefix[:], uints.NewU8Array(prefixBytes))
	copy(innerAssignment.CurrTxPost[:], uints.NewU8Array(postfixBytes))
	copy(innerAssignment.PrevTxId[:], uints.NewU8Array(prevTxnIdBytes))
	copy(innerAssignment.CurrTxId[:], uints.NewU8Array(currTxId[:]))

	innerWitness, err := frontend.NewWitness(innerAssignment, innerField)

	return innerWitness, err
}

func GenerateInnerProof(innerWitness witness.Witness, innerCcs constraint.ConstraintSystem, innerPK native_plonk.ProvingKey) (native_plonk.Proof, error) {
	innerField := ecc.BLS12_377.ScalarField()
	outerField := ecc.BW6_761.ScalarField()

	innerProof, err := native_plonk.Prove(innerCcs, innerPK, innerWitness, plonk.GetNativeProverOptions(outerField, innerField))

	return innerProof, err

}

func VerifyInnerProof(publicWitness witness.Witness, innerProof native_plonk.Proof, innerVK native_plonk.VerifyingKey) bool {
	innerField := ecc.BLS12_377.ScalarField()
	outerField := ecc.BW6_761.ScalarField()

	err := native_plonk.Verify(innerProof, innerVK, publicWitness, plonk.GetNativeVerifierOptions(outerField, innerField))

	if err == nil {
		return true
	} else {
		fmt.Println(err)
		return false
	}
}

func SetupOuterProof() {

}

func GenerateOuterProof() {

}

func VerifyOuterProof() {

}

// export
func GenerateAndVerify() string {

	logger := log.New(os.Stdout, "INFO: ", log.Ltime)

	start := time.Now()
	var circuit recurse.Sha256InnerCircuit

	fmt.Println(len([]byte("something")))

	arithCircuit, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	progress := time.Since(start)
	message := fmt.Sprintf("Circuit Compile took : %s \n", progress)
	logger.Print(message)

	if err != nil {
		return "Error compiling circuit"
	}

	start = time.Now()
	pk, vk, err := groth16.Setup(arithCircuit)

	progress = time.Since(start)
	message = fmt.Sprintf("%sCircuit Setup took : %s \n ", message, progress)
	logger.Print(message)

	if err != nil {
		return "Error during setup"
	}

	start = time.Now()

	//initialize the fullWitness assignment
	digest, _ := hex.DecodeString("3fc9b689459d738f8c88a3a48aa9e33542016b7a4052e001aaa536fca74813cb")

	var tmpHash [32]uints.U8

	copy(tmpHash[:], uints.NewU8Array(digest[:]))
	assignment := &recurse.Sha256InnerCircuit{
		CurrTxId: tmpHash,
	}
	copy(assignment.CurrTxId[:], uints.NewU8Array([]byte("something")))

	//fmt.Println(hex.EncodeToString(digest[:]))

	//generate fullWitness
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())

	if err != nil {
		return "Failed to create new Witness object"
	}

	start = time.Now()

	logger.Println("Creating proof...")
	proof, err := groth16.Prove(arithCircuit, pk, fullWitness)
	if err != nil {
		return "proof generation failed"
	}

	progress = time.Since(start)
	message = fmt.Sprintf("%sProof generation took : %s \n ", message, progress)
	logger.Print(message)

	logger.Println("Creating public fullWitness...")
	publicWitness, err := fullWitness.Public()
	if err != nil {
		return "Failed to create public fullWitness object"
	}

	progress = time.Since(start)

	logger.Println("Verifying proof...")
	err = groth16.Verify(proof, vk, publicWitness)

	if err != nil {
		return "proof verification failed !"
	}

	progress = time.Since(start)
	message = fmt.Sprintf("%sProof verify took : %s \n", message, progress)
	logger.Print(message)

	return message
}
