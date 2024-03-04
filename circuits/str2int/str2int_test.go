package str2int

import (
	"encoding/hex"
	utils "gadgets/utils"
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// Common setup function for both tests
func setupRecordWrapper() (Str2IntWrapper, Str2IntWrapper) {

	plainChunks := "302c353631204575726f227d2c227072696365223a2233383030322e32222c22"
	valueStart := 22
	valueEnd := 27
	value := 38002

	// convert to bytes
	byteSlice, _ := hex.DecodeString(plainChunks)
	plainChunksByteLen := len(byteSlice)

	// witness definition
	plainChunksAssign := utils.StrToIntSlice(plainChunks, true)

	// witness values preparation
	assignment := Str2IntWrapper{
		PlainChunks: make([]frontend.Variable, plainChunksByteLen),
		Value:       value,
		ValueStart:  valueStart,
		ValueEnd:    valueEnd,
	}

	// assign values here because required to use make in assignment
	for i := 0; i < plainChunksByteLen; i++ {
		assignment.PlainChunks[i] = plainChunksAssign[i]
	}

	// var circuit kdcServerKey
	circuit := Str2IntWrapper{
		PlainChunks: make([]frontend.Variable, plainChunksByteLen),
		Value:       value,
		ValueStart:  valueStart,
		ValueEnd:    valueEnd,
	}

	return circuit, assignment
}

// Test for Solving
func TestRecordSolving(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, assignment := setupRecordWrapper()

	// Solve the circuit and assert.
	assert.SolvingSucceeded(&circuit, &assignment, test.WithBackends(backend.GROTH16))
}

// Test for Proving
func TestRecordProving(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, assignment := setupRecordWrapper()

	// Proof successfully generated
	assert.ProverSucceeded(&circuit, &assignment)
}
