package hmacMIMC

import (
	utils "circuits/utils"

	"github.com/consensys/gnark/frontend"
	mimc "github.com/consensys/gnark/std/hash/mimc"
)

const B = 64 // Assuming B is a constant and equals 64

type HMACMiMCWrapper struct {
	K    []frontend.Variable
	Text []frontend.Variable
	// Expected []frontend.Variable
}

func (circuit *HMACMiMCWrapper) Define(api frontend.API) error {
	hmacMIMC := NewHMAC(api)

	innerHash := hmacMIMC.InnerHash(circuit.K, circuit.Text)

	hmacMIMC.OuterHash(circuit.K, innerHash)

	// constraint check
	// for i := 0; i < len(circuit.Expected); i++ {
	// 	api.AssertIsEqual(circuit.Expected[i], HMAC[i])
	// }
	return nil
}

func NewHMAC(api frontend.API) HMAC {
	return HMAC{api: api}
}

type HMAC struct {
	api frontend.API
}

func (hmac *HMAC) InnerHash(key []frontend.Variable, text []frontend.Variable) []frontend.Variable {
	// gadget imports
	mimcHash, _ := mimc.NewMiMC(hmac.api)

	expandedKey := make([]frontend.Variable, B)

	// First K bits are the key
	copy(expandedKey[:], key)

	// Append 0 until 64
	zeroes := make([]frontend.Variable, B-len(key))
	for i := range zeroes {
		zeroes[i] = frontend.Variable(0)
	}
	copy(expandedKey[len(key):], zeroes)

	innerPreImage := make([]frontend.Variable, B)
	for i := 0; i < B; i++ {
		innerPreImage[i] = utils.VariableXor(hmac.api, expandedKey[i], frontend.Variable(0x36), 8)
	}

	// Creating a new slice to hold the concatenated result
	totalLength := B + len(text)
	concatenatedSlice := make([]frontend.Variable, totalLength)

	// Copying innerPreImage to the new slice
	copy(concatenatedSlice, innerPreImage)

	// Copying text to the new slice
	copy(concatenatedSlice[B:], text)

	mimcHash.Write(concatenatedSlice[:]...)

	result := mimcHash.Sum()
	return []frontend.Variable{result}
}

func (hmac *HMAC) OuterHash(key []frontend.Variable, innerHash []frontend.Variable) []frontend.Variable {
	// gadget imports
	mimcHash, _ := mimc.NewMiMC(hmac.api)

	expandedKey := make([]frontend.Variable, B)

	// First K bits are the key
	copy(expandedKey[:], key)

	// Append 0 until 64
	zeroes := make([]frontend.Variable, B-len(key))
	for i := range zeroes {
		zeroes[i] = frontend.Variable(0)
	}
	copy(expandedKey[len(key):], zeroes)

	// opad is the outer padding constant, 0x5C repeated B times
	opad := frontend.Variable(0x5C)

	// xor the expandedKey with opad
	outerPreImage := make([]frontend.Variable, B)
	for i := 0; i < B; i++ {
		outerPreImage[i] = utils.VariableXor(hmac.api, expandedKey[i], opad, 8) // Assuming 8 bits per byte here
	}

	// Creating a new slice to hold the concatenated result
	totalLength := B + len(innerHash)
	concatenatedSlice := make([]frontend.Variable, totalLength)

	// Copying innerPreImage to the new slice
	copy(concatenatedSlice, outerPreImage)

	// Copying innerHash to the new slice
	copy(concatenatedSlice[B:], innerHash)

	// Compute the outer hash
	mimcHash.Write(concatenatedSlice[:]...)

	outerHash := mimcHash.Sum()
	return []frontend.Variable{outerHash}
}
