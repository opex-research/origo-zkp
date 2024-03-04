package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	utils "circuits/utils"
)

type HMACParams struct {
	Key  string `json:"key"`
	Text string `json:"text"`
}

const HMACExample = `{
    "key": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    "text": "54686520717569636b2062726f776e20666f78"
}`

// Common setup function for both tests
func setupHMACWrapper() (HMACWrapper, HMACWrapper) {

	var data HMACParams
	err := json.Unmarshal([]byte(HMACExample), &data)
	if err != nil {
		panic(err)
	}

	// Compute the expected HMAC using crypto/hmac
	expectedHMAC := computeHMAC(data.Key, data.Text)

	// fmt.Printf("Expected HMAC: %s\n", expectedHMAC)

	key := data.Key
	text := data.Text

	// Decode hex strings to bytes
	keyBytes, _ := hex.DecodeString(key)
	textBytes, _ := hex.DecodeString(text)
	expectedBytes, _ := hex.DecodeString(expectedHMAC)

	keyAssign := utils.StrToIntSlice(key, true)
	textAssign := utils.StrToIntSlice(text, true)
	expectedAssign := utils.StrToIntSlice(expectedHMAC, true)

	// witness values preparation
	assignment := HMACWrapper{
		K:        make([]frontend.Variable, len(keyBytes)),
		Text:     make([]frontend.Variable, len(textBytes)),
		Expected: make([]frontend.Variable, 32), // HMAC-SHA256 produces a 32-byte output
	}

	// Assign values to K
	for i := 0; i < len(keyBytes); i++ {
		assignment.K[i] = keyAssign[i]
	}
	// Assign values to text
	for i := 0; i < len(textBytes); i++ {
		assignment.Text[i] = textAssign[i]
	}
	// Assign values to Expected
	for i := 0; i < len(expectedBytes); i++ {
		assignment.Expected[i] = expectedAssign[i]
	}

	// log.Debug().Msgf("Sequence Number Assign: %v", keyAssign)
	// log.Debug().Msgf("Sequence Number Assign: %v", textAssign)

	// circuit
	circuit := HMACWrapper{
		K:        make([]frontend.Variable, len(keyBytes)),      // Initialize slice with proper length
		Text:     make([]frontend.Variable, len(textBytes)),     // Initialize slice with proper length
		Expected: make([]frontend.Variable, len(expectedBytes)), // Initialize slice with proper length
	}

	return circuit, assignment
}

func computeHMAC(key, text string) string {
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		panic(err)
	}
	textBytes, err := hex.DecodeString(text)
	if err != nil {
		panic(err)
	}

	h := hmac.New(sha256.New, keyBytes)
	h.Write(textBytes)
	return hex.EncodeToString(h.Sum(nil))
}

// Test for Solving
func TestHMACSolving(t *testing.T) {

	assert := test.NewAssert(t)
	circuit, assignment := setupHMACWrapper()

	// expectedHMAC := computeHMAC(data.Key, data.Text)

	assert.SolvingSucceeded(&circuit, &assignment, test.WithBackends(backend.GROTH16))
}

// Test for Proving
func TestHMACProving(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, assignment := setupHMACWrapper()

	// Proof successfully generated
	assert.ProverSucceeded(&circuit, &assignment)
}

func BenchmarkHMACProof(b *testing.B) {
	circuit, assignment := setupHMACWrapper()
	utils.BenchProof(b, &circuit, &assignment)
}
