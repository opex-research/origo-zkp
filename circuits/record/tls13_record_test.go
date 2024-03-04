package record

import (
	utils "circuits/utils"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type RecordParams struct {
	Key            string `json:"key"`
	Iv             string `json:"iv"`
	ChipherChunks  string `json:"cipher_chunks"`
	PlainChunks    string `json:"plain_chunks"`
	ChunkIndex     int    `json:"chunk_index"`
	Substring      string `json:"substring"`
	SubstringStart int    `json:"substring_start"`
	SubstringEnd   int    `json:"substring_end"`
	ValueStart     int    `json:"value_start"`
	ValueEnd       int    `json:"value_end"`
	Threshold      int    `json:"threshold"`
}

const RecordStr = `{
    "key": "2872658573f95e87550cb26374e5f667",
    "iv": "a54613bf2801a84ce693d0a0",
    "cipher_chunks": "419a031754a4897806533c6020e9130f6088747b9f9a1e1eba4cb0518a6d5692",
    "plain_chunks": "302c353631204575726f227d2c227072696365223a2233383030322e32222c22",
    "chunk_index": 32,
    "substring": "\"price\"",
    "substring_start": 13,
    "substring_end": 20,
    "value_start": 23,
    "value_end": 28,
    "threshold": 38003
}`

//  "keySapp": "cb4fc6613f59776c271268f867fd91d4",
// {"level":"debug","time":"2023-10-16T09:48:49+02:00","message":"iv: 668a9ed2883f5d9c96832f31"}
// {"level":"debug","time":"2023-10-16T09:48:49+02:00","message":"cipherChunks: e016d41de7a9c8ff41a80433ba1c448b960833d92ddf2b891fc00c32104d8d4a"}
// {"level":"debug","time":"2023-10-16T09:48:49+02:00","message":"plainChunks: 5344222c2276616c7565223a2233383030322e3230222c22627265616b646f77"}
// {"level":"debug","time":"2023-10-16T09:48:49+02:00","message":"chunkIndex: 11"}
// {"level":"debug","time":"2023-10-16T09:48:49+02:00","message":"substring: \"value\""}
// {"level":"debug","time":"2023-10-16T09:48:49+02:00","message":"substringStart: 4"}
// {"level":"debug","time":"2023-10-16T09:48:49+02:00","message":"substringEnd: 11"}
// {"level":"debug","time":"2023-10-16T09:48:49+02:00","message":"valueStart: 13"}
// {"level":"debug","time":"2023-10-16T09:48:49+02:00","message":"valueEnd: 18"}
// {"level":"debug","time":"2023-10-16T09:48:49+02:00","message":"threshold: 38001"}

const RecordStrPayPal = `{
    "key": "cb4fc6613f59776c271268f867fd91d4",
    "iv": "668a9ed2883f5d9c96832f31",
	"chunk_index": 11,
	"cipher_chunks": "e016d41de7a9c8ff41a80433ba1c448b960833d92ddf2b891fc00c32104d8d4a",
	"substring": "\"value\"",
	"substring_end": 11,
	"substring_start": 4,
	"value_end": 18,
	"value_start": 13,
    "plain_chunks": "5344222c2276616c7565223a2233383030322e3230222c22627265616b646f77",
    "threshold": 38001
}`

// Common setup function for both tests
func setupRecordWrapper() (RecordWrapper, RecordWrapper) {

	var data RecordParams
	err := json.Unmarshal([]byte(RecordStrPayPal), &data)
	if err != nil {
		panic(err)
	}

	// Now use data to initialize the RecordWrapper
	key := data.Key
	iv := data.Iv
	chipherChunks := data.ChipherChunks
	plainChunks := data.PlainChunks
	chunkIndex := data.ChunkIndex
	substring := data.Substring
	substringStart := data.SubstringStart
	substringEnd := data.SubstringEnd
	valueStart := data.ValueStart
	valueEnd := data.ValueEnd
	threshold := data.Threshold

	// record to bytes
	byteSlice, _ := hex.DecodeString(key)
	keyByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(iv)
	ivByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(chipherChunks)
	chipherChunksByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(plainChunks)
	plainChunksByteLen := len(byteSlice)
	substringByteLen := len(substring)

	// witness definition
	keyAssign := utils.StrToIntSlice(key, true)
	ivAssign := utils.StrToIntSlice(iv, true)
	chipherChunksAssign := utils.StrToIntSlice(chipherChunks, true)
	plainChunksAssign := utils.StrToIntSlice(plainChunks, true)
	substringAssign := utils.StrToIntSlice(substring, false)

	// witness values preparation
	assignment := RecordWrapper{
		Key:            [16]frontend.Variable{},
		PlainChunks:    make([]frontend.Variable, plainChunksByteLen),
		Iv:             [12]frontend.Variable{},
		CipherChunks:   make([]frontend.Variable, chipherChunksByteLen),
		ChunkIndex:     chunkIndex,
		Substring:      make([]frontend.Variable, substringByteLen),
		SubstringStart: substringStart,
		SubstringEnd:   substringEnd,
		ValueStart:     valueStart,
		ValueEnd:       valueEnd,
		Threshold:      threshold,
	}

	// kdc assign
	for i := 0; i < keyByteLen; i++ {
		assignment.Key[i] = keyAssign[i]
	}
	for i := 0; i < plainChunksByteLen; i++ {
		assignment.PlainChunks[i] = plainChunksAssign[i]
	}
	for i := 0; i < ivByteLen; i++ {
		assignment.Iv[i] = ivAssign[i]
	}
	for i := 0; i < chipherChunksByteLen; i++ {
		assignment.CipherChunks[i] = chipherChunksAssign[i]
	}
	for i := 0; i < substringByteLen; i++ {
		assignment.Substring[i] = substringAssign[i]
	}

	// var circuit kdcServerKey
	circuit := RecordWrapper{
		PlainChunks:    make([]frontend.Variable, plainChunksByteLen),
		CipherChunks:   make([]frontend.Variable, chipherChunksByteLen),
		Substring:      make([]frontend.Variable, substringByteLen),
		SubstringStart: substringStart,
		SubstringEnd:   substringEnd,
		ValueStart:     valueStart,
		ValueEnd:       valueEnd,
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
