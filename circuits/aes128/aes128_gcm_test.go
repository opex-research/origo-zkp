package aes128

import (
	utils "circuits/utils"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/rs/zerolog/log"
)

type AES128GCMParams struct {
	Key            string `json:"key"`
	IVBytes        string `json:"ivBytes"`
	ByteSize       int    `json:"byte_size"`
	ChunkIndex     int    `json:"chunk_index"`
	Plaintext      string `json:"plaintext"`
	Ciphertext     string `json:"ciphertext"`
	SequenceNumber string `json:"sequence_number"`
}

const AES128GCMStr = `{
    "key": "ab72c77b97cb5fe9a382d9fe81ffdbed",
	"ivBytes": "54cc7dc2c37ec006bcc6d1da",
    "byte_size": 16,
    "chunk_index": 2
}`

// PayPal response - value of interest is in second record, hence it requires XOR with sequence number
const AES128GCMStrPayPal = `{
    "key": "388ba3e1baea1a4c531db91b631d69c8",
	"ivBytes": "f3e113c7fc4206b0410d1125",
    "byte_size": 32,
    "chunk_index": 11,
	"plaintext": "5344222c2276616c7565223a2233383030322e3230222c22627265616b646f77",
	"ciphertext": "a1526c1957d1dc7c6e703880c62c7fdbff9a5071d15c05bcf9632ce82b10c7de",
	"sequence_number": "0000000000000001"
}`

// cipher - a1526c1957d1dc7c6e703880c62c7fdbff9a5071d15c05bcf9632ce82b10c7de

// Common setup function for both tests
func setupGCMWrapper() (GCMWrapper, GCMWrapper) {

	var data AES128GCMParams
	err := json.Unmarshal([]byte(AES128GCMStrPayPal), &data)
	if err != nil {
		panic(err)
	}

	key := data.Key
	ivBytes := data.IVBytes
	chunkIndex := data.ChunkIndex

	plainChunks := data.Plaintext
	plaintext, _ := hex.DecodeString(plainChunks)

	cipherChunks := data.Ciphertext
	ciphertext, _ := hex.DecodeString(cipherChunks)

	sequenceNumberHex := data.SequenceNumber
	sequenceNumber, _ := hex.DecodeString(sequenceNumberHex)

	aesIV, _ := hex.DecodeString(ivBytes)
	nonce := aesIV

	nonceString := hex.EncodeToString(nonce)
	plaintextString := hex.EncodeToString(plaintext)
	ciphertextString := hex.EncodeToString(ciphertext)
	sequenceNumberString := hex.EncodeToString(sequenceNumber)

	// convert to bytes
	byteSlice, _ := hex.DecodeString(key)
	keyByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(nonceString)
	nonceByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(plaintextString)
	ptByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(ciphertextString)
	ctByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(sequenceNumberString)
	seqByteLen := len(byteSlice)

	// witness definition
	keyAssign := utils.StrToIntSlice(key, true)
	nonceAssign := utils.StrToIntSlice(nonceString, true)
	ptAssign := utils.StrToIntSlice(plaintextString, true)
	ctAssign := utils.StrToIntSlice(ciphertextString, true)
	seqAssign := utils.StrToIntSlice(sequenceNumberString, true)

	log.Debug().Msgf("Sequence Number Assign: %v", seqAssign)

	// witness values preparation
	assignment := GCMWrapper{
		PlainChunks:    make([]frontend.Variable, ptByteLen),
		CipherChunks:   make([]frontend.Variable, ctByteLen),
		ChunkIndex:     chunkIndex, // frontend.Variable(chunkIdx),
		Iv:             [12]frontend.Variable{},
		Key:            [16]frontend.Variable{}, // make([]frontend.Variable, 16), //[16]frontend.Variable{},
		SequenceNumber: [8]frontend.Variable{},
	}

	// assign values here because required to use make in assignment
	for i := 0; i < ptByteLen; i++ {
		assignment.PlainChunks[i] = ptAssign[i]
	}
	for i := 0; i < ctByteLen; i++ {
		assignment.CipherChunks[i] = ctAssign[i]
	}
	for i := 0; i < nonceByteLen; i++ {
		assignment.Iv[i] = nonceAssign[i]
	}
	for i := 0; i < keyByteLen; i++ {
		assignment.Key[i] = keyAssign[i]
	}
	for i := 0; i < seqByteLen; i++ {
		assignment.SequenceNumber[i] = seqAssign[i]
	}

	// var circuit kdcServerKey
	circuit := GCMWrapper{
		PlainChunks:  make([]frontend.Variable, ptByteLen),
		CipherChunks: make([]frontend.Variable, ctByteLen),
		ChunkIndex:   chunkIndex,
	}

	return circuit, assignment
}

// Test for Solving
func TestAES128GCMSolving(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, assignment := setupGCMWrapper()

	// Solve the circuit and assert.
	assert.SolvingSucceeded(&circuit, &assignment, test.WithBackends(backend.GROTH16))
}

// Test for Proving
func TestAES128GCMProving(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, assignment := setupGCMWrapper()

	// Proof successfully generated
	assert.ProverSucceeded(&circuit, &assignment)
}
