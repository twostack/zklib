package zklib

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
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

/*
func SetupOuterProof(
	innerCcs constraint.ConstraintSystem,
	innerVK native_plonk.VerifyingKey,
	innerWitness witness.Witness,
	innerProof native_plonk.Proof,
	prevTxnIdBytes []byte, //, _ := hex.DecodeString("193a78f8a6883ae82d7e9f146934af4d6edc2f0f5a16d0b931bdfaa9a0d22eac")
) {

	//innerCcs, innerVK, innerWitness, innerProof := computeInnerProofPlonk(assert, ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField())

	circuitVk, err := plonk.ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerVK)
	if err != nil {
		panic(err)
	}
	circuitWitness, err := plonk.ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	if err != nil {
		panic(err)
	}
	circuitProof, err := plonk.ValueOfProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	if err != nil {
		panic(err)
	}

	outerCircuit := &recurse.Sha256OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: plonk.PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
		Proof:        plonk.PlaceholderProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerCcs),
		VerifyingKey: circuitVk,
	}
	copy(outerCircuit.PrevTxId[:], uints.NewU8Array(prevTxnIdBytes))

	outerAssignment := &recurse.Sha256OuterCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
	}
	copy(outerAssignment.PrevTxId[:], uints.NewU8Array(prevTxnIdBytes))

	// compile the outer circuit
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, outerCircuit)
	if err != nil {
		panic("compile failed: " + err.Error())
	}

	// NB! UNSAFE! Use MPC.
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		panic(err)
	}

	// create PLONK setup. NB! UNSAFE
	pk, vk, err := native_plonk.Setup(ccs, srs, srsLagrange) // UNSAFE! Use MPC
	if err != nil {
		panic("setup failed: " + err.Error())
	}

	// create prover witness from the assignment
	secretWitness, err := frontend.NewWitness(outerAssignment, ecc.BW6_761.ScalarField())
	if err != nil {
		panic("secret witness failed: " + err.Error())
	}

	// create public witness from the assignment
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic("public witness failed: " + err.Error())
	}

}

*/

func GenerateOuterProof(
	ccs constraint.ConstraintSystem,
	pk native_plonk.ProvingKey,
	secretWitness witness.Witness) (native_plonk.Proof, error) {

	// construct the PLONK proof of verifying PLONK proof in-circuit
	outerProof, err := native_plonk.Prove(ccs, pk, secretWitness)
	if err != nil {
		panic("proving failed: " + err.Error())
	}

	return outerProof, err
}

func VerifyOuterProof(outerProof native_plonk.Proof, vk native_plonk.VerifyingKey, publicWitness witness.Witness) {

	// verify the PLONK proof
	err := native_plonk.Verify(outerProof, vk, publicWitness)
	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}
}

// export
