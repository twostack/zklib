package recurse

/*
Example code provided by ivokub on Github related to recursive witness issues

https://github.com/Consensys/gnark/discussions/1081
*/

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	recursive_groth16 "github.com/consensys/gnark/std/recursion/groth16"
	recursive_plonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
	"testing"
)

type innerCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *innerCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, c.Y)
	return nil
}

type outerCircuitPlonk struct {
	VKey         recursive_plonk.VerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]
	Proof        recursive_plonk.Proof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine]
	InnerWitness recursive_plonk.Witness[sw_bn254.ScalarField]
}

func (c *outerCircuitPlonk) Define(api frontend.API) error {

	verifier, err := recursive_plonk.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		panic(err)
	}

	return verifier.AssertProof(c.VKey, c.Proof, c.InnerWitness, recursive_plonk.WithCompleteArithmetic())
}

type outerCircuitGroth16 struct {
	VKey         recursive_groth16.VerifyingKey[G1Affine, G2Affine, GTEl]
	Proof        recursive_groth16.Proof[G1Affine, G2Affine]
	InnerWitness recursive_groth16.Witness[ScalarField]
}

func (c *outerCircuitGroth16) Define(api frontend.API) error {

	//curve , err := algebra.GetCurve[ScalarField, G1Affine](api)
	//pairing, err := algebra.GetPairing[G1Affine, G2Affine, GTEl](api)

	verifier, err := recursive_groth16.NewVerifier[ScalarField, G1Affine, G2Affine, GTEl](api)
	if err != nil {
		panic(err)
	}

	return verifier.AssertProof(c.VKey, c.Proof, c.InnerWitness, recursive_groth16.WithCompleteArithmetic())
}

func TestRecursiveWitnessBN254(t *testing.T) {
	assert := test.NewAssert(t)

	inner := innerCircuit{}
	ccsInner, _ := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &inner)
	scsInner := ccsInner.(*cs.SparseR1CS)

	srs, srsLagrange, err := unsafekzg.NewSRS(scsInner, unsafekzg.WithFSCache())
	assert.NoError(err)
	pkInner, vkInner, err := plonk.Setup(ccsInner, srs, srsLagrange)
	assert.NoError(err)

	wInner := innerCircuit{X: 5, Y: 5}
	witnessInner, err := frontend.NewWitness(&wInner, ecc.BN254.ScalarField())
	assert.NoError(err)

	proofInner, err := plonk.Prove(ccsInner, pkInner, witnessInner,
		recursive_plonk.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)

	witnessInnerPublic, err := witnessInner.Public()
	assert.NoError(err)

	err = plonk.Verify(proofInner, vkInner, witnessInnerPublic,
		recursive_plonk.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)

	recursiveProof, err := recursive_plonk.ValueOfProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](proofInner)
	assert.NoError(err)

	recursiveVK, err := recursive_plonk.ValueOfVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](vkInner)
	assert.NoError(err)

	outer := outerCircuitPlonk{
		VKey:         recursive_plonk.PlaceholderVerifyingKey[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccsInner),
		Proof:        recursive_plonk.PlaceholderProof[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine](ccsInner),
		InnerWitness: recursive_plonk.PlaceholderWitness[sw_bn254.ScalarField](ccsInner),
	}

	innerWitness, err := recursive_plonk.ValueOfWitness[sw_bn254.ScalarField](witnessInnerPublic)
	assert.NoError(err)

	outerW := outerCircuitPlonk{
		VKey:         recursiveVK,
		Proof:        recursiveProof,
		InnerWitness: innerWitness,
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &outer)
	assert.NoError(err)

	srs2, srsLagrange2, err := unsafekzg.NewSRS(ccs, unsafekzg.WithFSCache())
	assert.NoError(err)

	pk, vk, err := plonk.Setup(ccs, srs2, srsLagrange2)
	assert.NoError(err)

	fmt.Println("proving ...")
	outerWitess, err := frontend.NewWitness(&outerW, ecc.BN254.ScalarField())
	assert.NoError(err)

	proof, err := plonk.Prove(ccs, pk, outerWitess,
		recursive_plonk.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)

	fmt.Println("verifying ...")
	pubOuterWitness, err := outerWitess.Public()
	assert.NoError(err)

	err = plonk.Verify(proof, vk, pubOuterWitness,
		recursive_plonk.GetNativeVerifierOptions(ecc.BN254.ScalarField(), ecc.BN254.ScalarField()))
	assert.NoError(err)
}

func TestRecursiveWitnessBLS12(t *testing.T) {
	assert := test.NewAssert(t)

	inner := innerCircuit{}
	ccsInner, _ := frontend.Compile(InnerCurve.ScalarField(), r1cs.NewBuilder, &inner)

	pkInner, vkInner, err := groth16.Setup(ccsInner)
	assert.NoError(err)

	wInner := innerCircuit{X: 5, Y: 5}
	witnessInner, err := frontend.NewWitness(&wInner, InnerCurve.ScalarField())
	assert.NoError(err)

	proofInner, err := groth16.Prove(ccsInner, pkInner, witnessInner,
		recursive_groth16.GetNativeProverOptions(OuterCurve.ScalarField(), InnerCurve.ScalarField()))
	assert.NoError(err)

	witnessInnerPublic, err := witnessInner.Public()
	assert.NoError(err)

	err = groth16.Verify(proofInner, vkInner, witnessInnerPublic,
		recursive_groth16.GetNativeVerifierOptions(OuterCurve.ScalarField(), InnerCurve.ScalarField()))
	assert.NoError(err)

	recursiveProof, err := recursive_groth16.ValueOfProof[G1Affine, G2Affine](proofInner)
	assert.NoError(err)

	recursiveVK, err := recursive_groth16.ValueOfVerifyingKey[G1Affine, G2Affine, GTEl](vkInner)
	assert.NoError(err)

	outer := outerCircuitGroth16{
		VKey:         recursive_groth16.PlaceholderVerifyingKey[G1Affine, G2Affine, GTEl](ccsInner),
		Proof:        recursive_groth16.PlaceholderProof[G1Affine, G2Affine](ccsInner),
		InnerWitness: recursive_groth16.PlaceholderWitness[ScalarField](ccsInner),
	}

	innerWitness, err := recursive_groth16.ValueOfWitness[ScalarField](witnessInnerPublic)
	assert.NoError(err)

	outerW := outerCircuitGroth16{
		VKey:         recursiveVK,
		Proof:        recursiveProof,
		InnerWitness: innerWitness,
	}

	ccs, err := frontend.Compile(OuterCurve.ScalarField(), r1cs.NewBuilder, &outer)
	assert.NoError(err)

	pk, vk, err := groth16.Setup(ccs)
	assert.NoError(err)

	fmt.Println("proving ...")
	outerWitess, err := frontend.NewWitness(&outerW, OuterCurve.ScalarField())
	assert.NoError(err)

	proof, err := groth16.Prove(ccs, pk, outerWitess,
		recursive_groth16.GetNativeProverOptions(OuterCurve.ScalarField(), OuterCurve.ScalarField()))
	assert.NoError(err)

	fmt.Println("verifying ...")
	pubOuterWitness, err := outerWitess.Public()
	assert.NoError(err)

	err = groth16.Verify(proof, vk, pubOuterWitness,
		recursive_groth16.GetNativeVerifierOptions(OuterCurve.ScalarField(), InnerCurve.ScalarField()))
	assert.NoError(err)
}
