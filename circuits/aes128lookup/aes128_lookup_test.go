package aes128lookup

import (
	"crypto/aes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	utils "circuits/utils"
)

type AES128Params struct {
	Key   string `json:"key"`
	Zeros string `json:"zeros"`
	ECBK  string `json:"ecbk"`
}

const AES128Str = `{
    "key": "2872658573f95e87550cb26374e5f667",
    "zeros": "00000000000000000000000000000000",
    "ecb0": "1c9c7c260c39bcb8dcfa5fbc9330b9fa"
}`

const AES128StrPayPal = `{
    "key": "f6f077cf8bfff92607c8ca6362f0948b",
    "zeros": "00000000000000000000000000000000",
    "ecbk": "2c02f543f56dd7abc50a4b35201be8cd"
}`

// Common setup function for both tests
func setupAES128Wrapper() (AES128Wrapper, AES128Wrapper) {

	var data AES128Params
	err := json.Unmarshal([]byte(AES128StrPayPal), &data)
	if err != nil {
		panic(err)
	}

	key := data.Key
	zeros := data.Zeros
	ecbk := data.ECBK

	byteSlice, _ := hex.DecodeString(key)
	keyByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(zeros)
	zerosByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(ecbk)
	ecbkByteLen := len(byteSlice)

	// witness definition kdc
	keyAssign := utils.StrToIntSlice(key, true)
	zerosAssign := utils.StrToIntSlice(zeros, true)
	ecbkAssign := utils.StrToIntSlice(ecbk, true)

	// calculate ciphertext ourselves
	block, err := aes.NewCipher(utils.MustHex(key))
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, len(utils.MustHex(zeros)))
	block.Encrypt(ciphertext, utils.MustHex(zeros))

	fmt.Printf("Calculated Ciphertext: %s\n", hex.EncodeToString(ciphertext))
	fmt.Printf("Expected Ciphertext: %s\n", ecbk)

	// witness values preparation
	assignment := AES128Wrapper{
		Plain:  [16]frontend.Variable{},
		Key:    [16]frontend.Variable{},
		Cipher: [16]frontend.Variable{},
	}

	// kdc assign
	for i := 0; i < zerosByteLen; i++ {
		assignment.Plain[i] = zerosAssign[i]
	}
	for i := 0; i < keyByteLen; i++ {
		assignment.Key[i] = keyAssign[i]
	}
	for i := 0; i < ecbkByteLen; i++ {
		assignment.Cipher[i] = ecbkAssign[i]
	}

	// var circuit kdcServerKey
	var circuit AES128Wrapper

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

func TestCompileGetConstraints(t *testing.T) {
	curve := ecc.BN254.ScalarField()

	_, assignment := setupAES128Wrapper()

	r1css, err := frontend.Compile(curve, r1cs.NewBuilder, &assignment)
	if err != nil {
		panic(err)
	}

	fmt.Printf("constraints: %d\n", r1css.GetNbConstraints())
}
