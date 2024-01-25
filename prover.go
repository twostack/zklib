package zklib

import (
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"time"
	groth162 "zklib/groth16"
)

//export
func GenerateAndVerify() string {

	start := time.Now()
	var circuit groth162.Sha256Circuit

	fmt.Println(len([]byte("something")))

	arithCircuit, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	progress := time.Since(start)
	message := fmt.Sprintf("Circuit Compile took : %s \n", progress)

	if err != nil {
		return "Error compiling circuit"
	}

	start = time.Now()
	pk, vk, err := groth16.Setup(arithCircuit)

	progress = time.Since(start)
	message = fmt.Sprintf("%sCircuit Setup took : %s \n ", message, progress)

	if err != nil {
		return "Error during setup"
	}

	start = time.Now()

	//initialize the fullWitness assignment
	digest, _ := hex.DecodeString("3fc9b689459d738f8c88a3a48aa9e33542016b7a4052e001aaa536fca74813cb")

	var tmpHash [32]uints.U8

	copy(tmpHash[:], uints.NewU8Array(digest[:]))
	assignment := &groth162.Sha256Circuit{
		Hash: tmpHash,
	}
	copy(assignment.PreImage[:], uints.NewU8Array([]byte("something")))

	//fmt.Println(hex.EncodeToString(digest[:]))

	//generate fullWitness
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())

	if err != nil {
		return "Failed to create new Witness object"
	}

	start = time.Now()

	fmt.Println("Creating proof...")
	proof, err := groth16.Prove(arithCircuit, pk, fullWitness)
	if err != nil {
		return "proof generation failed"
	}

	progress = time.Since(start)
	message = fmt.Sprintf("%sProof generation took : %s \n ", message, progress)

	fmt.Println("Creating public fullWitness...")
	publicWitness, err := fullWitness.Public()
	if err != nil {
		return "Failed to create public fullWitness object"
	}

	progress = time.Since(start)

	fmt.Println("Verifying proof...")
	err = groth16.Verify(proof, vk, publicWitness)

	if err != nil {
		return "proof verification failed !"
	}

	progress = time.Since(start)
	message = fmt.Sprintf("%sProof verify took : %s \n", message, progress)

	return message
}
