package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
	"zklib"
)

func main() {
	start := time.Now()
	//zklib.GenerateCircuitParams()
	//zklib.UnmarshalCircuitParams()
	testCreateAndVerify()
	end := time.Since(start)

	fmt.Printf("It took : %s", end)
}

func testCreateAndVerify() {

	start := time.Now()
	prefixBytes, _ := hex.DecodeString("0200000001")
	prevTxnIdBytes, _ := hex.DecodeString("ae4b7f1769154bb04e9c666a4dbb31eb2ec0c4e01d965cbb1ca4574e7ed40a19")
	postFixBytes, _ := hex.DecodeString("000000004847304402200e993f6bc2319615b662ac7f5882bc78dc35101d1b110a0edf2fd79dea2206c2022017e352e87390227a39b7eae6510cdff9e1cedc8a517e811b90ac6b6fdc8d7d0441feffffff0200ca9a3b000000001976a914783b608b9278a187641d047c14dbf63e1be5bc8888ac00196bee000000001976a9142bfccc428186e69fc94fde6d7396f19482dd5a7988ac65000000")
	fullTxBytes, _ := hex.DecodeString("0200000001ae4b7f1769154bb04e9c666a4dbb31eb2ec0c4e01d965cbb1ca4574e7ed40a19000000004847304402200e993f6bc2319615b662ac7f5882bc78dc35101d1b110a0edf2fd79dea2206c2022017e352e87390227a39b7eae6510cdff9e1cedc8a517e811b90ac6b6fdc8d7d0441feffffff0200ca9a3b000000001976a914783b608b9278a187641d047c14dbf63e1be5bc8888ac00196bee000000001976a9142bfccc428186e69fc94fde6d7396f19482dd5a7988ac65000000")

	firstHash := sha256.Sum256(fullTxBytes)
	currTxId := sha256.Sum256(firstHash[:])

	innerWitness, err := zklib.CreateInnerWitness(prefixBytes, prevTxnIdBytes, postFixBytes, currTxId[:])
	if err != nil {
		fmt.Println(err)
		return
	}
	end := time.Since(start)
	fmt.Printf("Inner witness assembled : %s\n", end)

	start = time.Now()
	innerCcs, err := zklib.CompileInnerCiruit()

	if err != nil {
		fmt.Println(err)
		return
	}
	end = time.Since(start)
	fmt.Printf("Circuit compiled : %s\n", end)

	start = time.Now()

	innerVK, innerPK, err := zklib.SetupCircuit(innerCcs)
	if err != nil {
		fmt.Println(err)
		return
	}
	end = time.Since(start)
	fmt.Printf("Circuit Setup: %s\n", end)

	start = time.Now()

	innerProof, err := zklib.GenerateInnerProof(innerWitness, innerCcs, innerPK)
	if err != nil {
		fmt.Println(err)
		return
	}
	end = time.Since(start)
	fmt.Printf("Generated Inner PreviousProof: %s\n", end)

	start = time.Now()

	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		fmt.Println(err)
		return
	}

	var isValid = zklib.VerifyInnerProof(innerPubWitness, innerProof, innerVK)

	if isValid == false {
		fmt.Println("PreviousProof Failed !")
	}

	end = time.Since(start)
	fmt.Printf("Verified Inner PreviousProof: %s\n", end)

}
