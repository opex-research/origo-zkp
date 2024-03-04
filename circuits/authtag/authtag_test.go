package authtag

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	utils "circuits/utils"
)

// Define the JSON struct
type AuthTagData struct {
	Key   string `json:"key"`
	IV    string `json:"iv"`
	Zeros string `json:"zeros"`
	ECB0  string `json:"ecb0"`
	ECBK  string `json:"ecbk"`
}

// Here's the constant JSON string:
const jsonData = `
{
	"key": "2872658573f95e87550cb26374e5f667",
	"iv": "a54613bf2801a84ce693d0a0",
	"zeros": "00000000000000000000000000000000",
	"ecb0": "a5cd49b7c29ad21fedbcedc01e0f13e8",
	"ecbk": "1c9c7c260c39bcb8dcfa5fbc9330b9fa"
}
`

// Key can be extracted from skdc_params.json as logged on the client side
const jsonDataPayPal = `
{
	"key": "e3a20014bcb3c28249a545919bc3b84a",
	"iv": "4b6d5bb8780b7707902093fa",
	"zeros": "00000000000000000000000000000000",
	"ecb0": "cd5389038a476a1b6a7592330e7b30e7",
	"ecbk": "147306c7dc9dc4ff4012a3f0af30c4b6"
}
`

// Common setup function for both tests
func setupAuthTagWrapper() (AuthTagWrapper, AuthTagWrapper) {

	var authTagData AuthTagData

	// Decode the JSON string into aesData
	if err := json.Unmarshal([]byte(jsonDataPayPal), &authTagData); err != nil {
		panic(err)
	}

	// Use values from aesData instead of hardcoded values
	key := authTagData.Key
	iv := authTagData.IV

	// add counter to iv bytes
	var sb strings.Builder
	for i := 0; i < len(iv); i++ {
		sb.WriteString(string(iv[i]))
	}
	for i := 0; i < 7; i++ {
		sb.WriteString("0")
	}
	sb.WriteString("2")
	ivCounter := sb.String()
	// fmt.Printf("Derived IV counter: %s\n", ivCounter)

	zeros := authTagData.Zeros
	ecb0 := authTagData.ECB0
	ecbk := authTagData.ECBK

	// convert to bytes
	byteSlice, _ := hex.DecodeString(key)
	keyByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(ivCounter)
	ivCounterByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(zeros)
	zerosByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(ecb0)
	ecb0ByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(ecbk)
	ecbkByteLen := len(byteSlice)

	// witness definition
	keyAssign := utils.StrToIntSlice(key, true)
	ivCounterAssign := utils.StrToIntSlice(ivCounter, true)
	zerosAssign := utils.StrToIntSlice(zeros, true)
	ecb0Assign := utils.StrToIntSlice(ecb0, true)
	ecbkAssign := utils.StrToIntSlice(ecbk, true)

	// witness values preparation
	assignment := AuthTagWrapper{
		Key:       [16]frontend.Variable{},
		IvCounter: [16]frontend.Variable{},
		Zeros:     [16]frontend.Variable{},
		ECB0:      [16]frontend.Variable{},
		ECBK:      [16]frontend.Variable{},
	}

	for i := 0; i < keyByteLen; i++ {
		assignment.Key[i] = keyAssign[i]
	}
	for i := 0; i < ivCounterByteLen; i++ {
		assignment.IvCounter[i] = ivCounterAssign[i]
	}
	for i := 0; i < zerosByteLen; i++ {
		assignment.Zeros[i] = zerosAssign[i]
	}
	for i := 0; i < ecbkByteLen; i++ {
		assignment.ECBK[i] = ecbkAssign[i]
	}
	for i := 0; i < ecb0ByteLen; i++ {
		assignment.ECB0[i] = ecb0Assign[i]
	}

	// var circuit kdcServerKey
	var circuit AuthTagWrapper

	return circuit, assignment
}

// Test for Solving
func TestKdcWrapperSolving(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, assignment := setupAuthTagWrapper()

	// Solve the circuit and assert.
	assert.SolvingSucceeded(&circuit, &assignment, test.WithBackends(backend.GROTH16))
}

// Test for Proving
func TestKdcWrapperProving(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, assignment := setupAuthTagWrapper()

	// Proof successfully generated
	assert.ProverSucceeded(&circuit, &assignment)
}
