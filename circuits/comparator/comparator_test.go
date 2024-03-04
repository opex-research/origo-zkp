package comparator

import (
	utils "circuits/utils"
	"encoding/hex"
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// Common setup function for both tests
func setupAES128Wrapper() (SubstringWrapper, SubstringWrapper) {

	plainChunks := "302c353631204575726f227d2c227072696365223a2233383030322e32222c22"
	substring := "\"price\""
	substringStart := 13
	substringEnd := 20

	// convert to bytes
	byteSlice, _ := hex.DecodeString(plainChunks)
	plainChunksByteLen := len(byteSlice)
	substringByteLen := len(substring)

	// witness definition
	plainChunksAssign := utils.StrToIntSlice(plainChunks, true)
	substringAssign := utils.StrToIntSlice(substring, false)

	// witness values preparation
	assignment := SubstringWrapper{
		PlainChunks:    make([]frontend.Variable, plainChunksByteLen),
		Substring:      make([]frontend.Variable, substringByteLen),
		SubstringStart: substringStart,
		SubstringEnd:   substringEnd,
	}

	// assign values here because required to use make in assignment
	for i := 0; i < plainChunksByteLen; i++ {
		assignment.PlainChunks[i] = plainChunksAssign[i]
	}
	for i := 0; i < substringByteLen; i++ {
		assignment.Substring[i] = substringAssign[i]
	}

	// var circuit kdcServerKey
	circuit := SubstringWrapper{
		PlainChunks:    make([]frontend.Variable, plainChunksByteLen),
		Substring:      make([]frontend.Variable, substringByteLen),
		SubstringStart: substringStart,
		SubstringEnd:   substringEnd,
	}

	return circuit, assignment
}

// Test for Solving
func TestAES128Solving(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, assignment := setupAES128Wrapper()

	// Solve the circuit and assert.
	assert.SolvingSucceeded(&circuit, &assignment, test.WithBackends(backend.GROTH16))
}

// Test for Proving
func TestAES128Proving(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, assignment := setupAES128Wrapper()

	// Proof successfully generated
	assert.ProverSucceeded(&circuit, &assignment)
}
