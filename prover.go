package zklib

import (
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

/*
Proof object to encapsulate the behaviour of
doing setup just once, and then repeatedly
constructing and verifying proofs and
*/
type ProofObj struct {
	ccs          constraint.ConstraintSystem
	verifyingKey native_plonk.VerifyingKey
	provingKey   native_plonk.ProvingKey
}

func CompileInnerCiruit() (constraint.ConstraintSystem, error) {
	innerField := ecc.BLS12_377.ScalarField()
	innerCcs, err := frontend.Compile(innerField, scs.NewBuilder, &recurse.Sha256InnerCircuit{})
	if err != nil {
		return nil, err
	}

	return innerCcs, nil
}

func SetupCircuit(innerCcs constraint.ConstraintSystem) (native_plonk.VerifyingKey, native_plonk.ProvingKey, error) {

	start := time.Now()
	srs, srsLagrange, err := unsafekzg.NewSRS(innerCcs)

	if err != nil {
		return nil, nil, err
	}

	innerPK, innerVK, err := native_plonk.Setup(innerCcs, srs, srsLagrange)
	if err != nil {
		return nil, nil, err
	}
	end := time.Since(start)
	fmt.Printf("Circuit Setup took : %s\n", end)

	return innerVK, innerPK, nil

}

func CreateInnerWitness(prefixBytes []byte, prevTxnIdBytes []byte, postfixBytes []byte, currTxId []byte) (witness.Witness, error) {
	innerField := ecc.BLS12_377.ScalarField()

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

// generate innerVK, innerPK, compiled circuit and save to disk
func GenerateCircuitParams() error {

	innerCcs, err := CompileInnerCiruit()

	if err != nil {
		fmt.Println(err)
		return err
	}

	innerVK, innerPK, err := SetupCircuit(innerCcs)

	//circuitFile, err := os.Create("circuit.json")
	//innerCcs.WriteTo(circuitFile)
	//if err != nil {
	//	log.Fatal(err)
	//	return err
	//}
	//circuitFile.Close()

	start := time.Now()
	innerVKFile, err := os.Create("innervk.cbor")
	innerVK.WriteTo(innerVKFile)
	if err != nil {
		log.Fatal(err)
		return err
	}
	innerVKFile.Close()
	end := time.Since(start)
	fmt.Printf("Writing Inner Verifying Key took : %s\n", end)

	start = time.Now()
	innerPKFile, err := os.Create("innerpk.cbor")
	innerPK.WriteTo(innerPKFile)
	if err != nil {
		log.Fatal(err)
		return err
	}
	innerPKFile.Close()
	end = time.Since(start)
	fmt.Printf("Writing Proving Key took : %s\n", end)

	return nil
}

func UnmarshalCircuitParams() (native_plonk.VerifyingKey, native_plonk.ProvingKey, constraint.ConstraintSystem, error) {

	//just compile. I don't think this takes long
	start := time.Now()
	ccs, err := CompileInnerCiruit()
	if err != nil {
		log.Fatal(err)
		return nil, nil, nil, err
	}
	end := time.Since(start)
	fmt.Printf("Compiler took : %s\n", end)

	start = time.Now()
	innerVKFile, err := os.OpenFile("innervk.cbor", os.O_RDONLY, 0444) //read-only
	if err != nil {
		log.Fatal(err)
		return nil, nil, nil, err
	}
	innerVK := native_plonk.NewVerifyingKey(ecc.BLS12_377) //curve for inner circuit
	innerVK.ReadFrom(innerVKFile)
	innerVKFile.Close()
	end = time.Since(start)
	fmt.Printf("Verifying Key took : %s\n", end)

	start = time.Now()
	innerPKFile, err := os.OpenFile("innerpk.cbor", os.O_RDONLY, 0444)
	if err != nil {
		log.Fatal(err)
		return nil, nil, nil, err
	}
	innerPK := native_plonk.NewProvingKey(ecc.BLS12_377) //curve for inner circuit
	innerPK.ReadFrom(innerPKFile)
	innerPKFile.Close()
	end = time.Since(start)
	fmt.Printf("Proving Key took : %s\n", end)

	return innerVK, innerPK, ccs, nil

}

//provide VK, PK and Circuit

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
