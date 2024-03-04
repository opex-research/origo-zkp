package hmacMIMC

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	utils "circuits/utils"
)

type HMACMiMCParams struct {
	Key  string `json:"key"`
	Text string `json:"text"`
}

const HMACMiMCExample = `{
    "key": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    "text": "54686520717569636b2062726f776e20666f78"
}`

func setupHMACMiMCWrapper() (HMACMiMCWrapper, HMACMiMCWrapper) {
	var data HMACMiMCParams
	err := json.Unmarshal([]byte(HMACMiMCExample), &data)
	if err != nil {
		panic(err)
	}

	// Compute the expected HMAC using MiMC
	// expectedHMAC := computeHMACMiMC(data.Key, data.Text)
	// fmt.Printf("Expected HMAC MiMC: %s\n", expectedHMAC)

	key := data.Key
	text := data.Text

	// Decode hex strings to bytes
	keyBytes, _ := hex.DecodeString(key)
	textBytes, _ := hex.DecodeString(text)
	// expectedBytes, _ := hex.DecodeString(expectedHMAC)

	keyAssign := utils.StrToIntSlice(key, true)
	textAssign := utils.StrToIntSlice(text, true)
	// expectedAssign := utils.StrToIntSlice(expectedHMAC, true)

	// witness values preparation
	assignment := HMACMiMCWrapper{
		K:    make([]frontend.Variable, len(keyBytes)),
		Text: make([]frontend.Variable, len(textBytes)),
		// Expected: make([]frontend.Variable, len(expectedBytes)), // Adjust size according to MiMC output
	}

	// Assign values
	for i := 0; i < len(keyBytes); i++ {
		assignment.K[i] = keyAssign[i]
	}
	for i := 0; i < len(textBytes); i++ {
		assignment.Text[i] = textAssign[i]
	}
	// for i := 0; i < len(expectedBytes); i++ {
	// 	assignment.Expected[i] = expectedAssign[i]
	// }

	// circuit
	circuit := HMACMiMCWrapper{
		K:    make([]frontend.Variable, len(keyBytes)),
		Text: make([]frontend.Variable, len(textBytes)),
		// Expected: make([]frontend.Variable, len(expectedBytes)),
	}

	return circuit, assignment
}

func TestHMACMiMCSolving(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, assignment := setupHMACMiMCWrapper()

	assert.SolvingSucceeded(&circuit, &assignment, test.WithBackends(backend.GROTH16))
}

func TestHMACMiMCProving(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, assignment := setupHMACMiMCWrapper()

	assert.ProverSucceeded(&circuit, &assignment)
}

func BenchmarkHMACMiMCProof(b *testing.B) {
	circuit, assignment := setupHMACMiMCWrapper()
	utils.BenchProof(b, &circuit, &assignment)
}
