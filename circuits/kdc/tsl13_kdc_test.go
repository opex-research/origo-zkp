package kdc

import (
	"encoding/hex"
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	utils "circuits/utils"
)

// Common setup function for both tests
func setupKdcWrapper() (KdcWrapper, KdcWrapper) {
	// Using provided hex values for the inputs.
	dhsInHex := "3352927e78c6f8ff6e09a9cdbd13f22f94467f85316bb1d4be826c449d2c7f9f"
	mSinHex := "36d9ab5e3faed3958c2ed545c7529426d766b2d5cd9422dccb7ca90c7a62579d"
	xatsInHex := "a274333afcd102039bb1bc0632e1488858375420a55937c878a6fbdb1915ca94"
	intermediateHashHSopadHex := "4b666cdc720a74082b1594c95367f3c71f5124db03add4877e959c6c50c7e3b5"
	tkXAPPinHex := "b7c39a10f4650ad160dfe8161ad74020ac50447768894252f7504aafb0c11d36"
	tkXAPPHex := "58e95f7a4abe43fa68c785039f09dce8"

	// kdc to bytes
	dHSSlice, _ := hex.DecodeString(dhsInHex)
	dHSinByteLen := len(dHSSlice)
	byteSlice, _ := hex.DecodeString(intermediateHashHSopadHex)
	intermediateHashHSopadByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(mSinHex)
	MSinByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(xatsInHex)
	XATSinByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(tkXAPPinHex)
	tkXAPPinByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(tkXAPPHex)
	tkXAPPByteLen := len(byteSlice)

	// add padding
	pad := utils.PadSha256(96)
	dHSinPadded := make([]byte, 32+len(pad))
	copy(dHSinPadded, dHSSlice)
	copy(dHSinPadded[32:], pad)
	newdHSin := hex.EncodeToString(dHSinPadded)
	dHSinByteLen += 32

	// Convert hex values to integer slices.
	dHSinAssign := utils.StrToIntSlice(newdHSin, true)
	intermediateHashHSopadAssign := utils.StrToIntSlice(intermediateHashHSopadHex, true)
	MSinAssign := utils.StrToIntSlice(mSinHex, true)
	XATSinAssign := utils.StrToIntSlice(xatsInHex, true)
	tkXAPPinAssign := utils.StrToIntSlice(tkXAPPinHex, true)
	tkXAPPAssign := utils.StrToIntSlice(tkXAPPHex, true)

	// Set up the witness using the arrays
	assignment := KdcWrapper{
		IntermediateHashHSopad: [32]frontend.Variable{},
		DHSin:                  [64]frontend.Variable{},
		MSin:                   [32]frontend.Variable{},
		XATSin:                 [32]frontend.Variable{},
		TkXAPPin:               [32]frontend.Variable{},
		TkXAPP:                 [16]frontend.Variable{},
	}

	// kdc assign
	for i := 0; i < intermediateHashHSopadByteLen; i++ {
		assignment.IntermediateHashHSopad[i] = intermediateHashHSopadAssign[i]
	}
	for i := 0; i < dHSinByteLen; i++ {
		assignment.DHSin[i] = dHSinAssign[i]
	}
	for i := 0; i < MSinByteLen; i++ {
		assignment.MSin[i] = MSinAssign[i]
	}
	for i := 0; i < XATSinByteLen; i++ {
		assignment.XATSin[i] = XATSinAssign[i]
	}
	for i := 0; i < tkXAPPinByteLen; i++ {
		assignment.TkXAPPin[i] = tkXAPPinAssign[i]
	}
	for i := 0; i < tkXAPPByteLen; i++ {
		assignment.TkXAPP[i] = tkXAPPAssign[i]
	}
	// auth

	// var circuit kdcServerKey
	var circuit KdcWrapper

	return circuit, assignment
}

// Test for Solving
func TestKdcWrapperSolving(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, assignment := setupKdcWrapper()

	// Solve the circuit and assert.
	assert.SolvingSucceeded(&circuit, &assignment, test.WithBackends(backend.GROTH16))
}

// Test for Proving
func TestKdcWrapperProving(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, assignment := setupKdcWrapper()

	// Proof successfully generated
	assert.ProverSucceeded(&circuit, &assignment)
}
