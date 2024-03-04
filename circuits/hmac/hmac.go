package hmac

import (
	sha256 "circuits/sha256"

	utils "circuits/utils"

	"github.com/consensys/gnark/frontend"
)

const B = 64 // Assuming B is a constant and equals 64

type HMACWrapper struct {
	K        []frontend.Variable
	Text     []frontend.Variable
	Expected []frontend.Variable
}

func (circuit *HMACWrapper) Define(api frontend.API) error {
	hmac := NewHMAC(api)

	innerHash := hmac.InnerHash(circuit.K, circuit.Text)

	HMAC := hmac.OuterHash(circuit.K, innerHash)

	// constraint check
	for i := 0; i < len(circuit.Expected); i++ {
		api.AssertIsEqual(circuit.Expected[i], HMAC[i])
	}
	return nil
}

func NewHMAC(api frontend.API) HMAC {
	return HMAC{api: api}
}

type HMAC struct {
	api frontend.API
}

func (hmac *HMAC) InnerHash(key []frontend.Variable, text []frontend.Variable) [32]frontend.Variable {

	// gadget imports
	sha := sha256.NewSHA256(hmac.api)

	expandedKey := make([]frontend.Variable, B)

	// THIS IS WHAT SHOULD BE APPEENDED
	p := frontend.Variable(0)

	// First K bits are the key
	copy(expandedKey[:], key)

	// Append 0 until 64
	zeroes := make([]frontend.Variable, B-len(key))
	for i := range zeroes {
		zeroes[i] = p
	}
	copy(expandedKey[len(key):], zeroes)

	// ipadBits := hmac.api.ToBinary(ipad, 32)

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

	sha.Write(concatenatedSlice)

	innerHash := sha.Sum()

	return innerHash
}

func (hmac *HMAC) OuterHash(key []frontend.Variable, innerHash [32]frontend.Variable) [32]frontend.Variable {
	// gadget imports
	sha := sha256.NewSHA256(hmac.api)

	// ExpandedKey will hold the outer padded key
	expandedKey := make([]frontend.Variable, B)

	// THIS IS WHAT SHOULD BE APPEENDED
	p := frontend.Variable(0)

	// First K bits are the key
	copy(expandedKey[:], key)

	// Append 0 until 64
	zeroes := make([]frontend.Variable, B-len(key))
	for i := range zeroes {
		zeroes[i] = p
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
	totalLength := B + 32
	concatenatedSlice := make([]frontend.Variable, totalLength)

	// Copying innerPreImage to the new slice
	copy(concatenatedSlice, outerPreImage)

	// Copying text to the new slice
	copy(concatenatedSlice[B:], innerHash[:])

	// log.Debug().Msgf("Sequence Number Assign: %v", concatenatedSlice)

	// Compute the outer hash
	sha.Write(concatenatedSlice)

	outerHash := sha.Sum()

	// log.Debug().Msgf("Sequence Number Assign: %v", outerHash)

	return outerHash
}
