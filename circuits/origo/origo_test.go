package origo

import (
	utils "circuits/utils"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type FinalParams struct {
	CATSin                 string `json:"CATSin"`
	ECB0                   string `json:"ECB0"`
	ECBK                   string `json:"ECBK"`
	MSin                   string `json:"MSin"`
	SATSin                 string `json:"SATSin"`
	ChunkIndex             int    `json:"chunk_index,string"`
	CipherChunks           string `json:"cipher_chunks"`
	DHSin                  string `json:"dHSin"`
	HashKeyCapp            string `json:"hashKeyCapp"`
	HashKeySapp            string `json:"hashKeySapp"`
	IntermediateHashHSopad string `json:"intermediateHashHSopad"`
	IvCapp                 string `json:"ivCapp"`
	IvSapp                 string `json:"ivSapp"`
	NumberChunks           int    `json:"number_chunks,string"`
	PlainChunks            string `json:"plain_chunks"`
	SizeAreaOfInterest     int    `json:"size_area_of_interest,string"`
	SizeValue              int    `json:"size_value,string"`
	Substring              string `json:"substring"`
	SubstringEnd           int    `json:"substring_end,string"`
	SubstringStart         int    `json:"substring_start,string"`
	SubstringStartIdx      int    `json:"substring_start_idx,string"`
	TkCAPPin               string `json:"tkCAPPin"`
	TkSAPPin               string `json:"tkSAPPin"`
	ValueEnd               int    `json:"value_end,string"`
	ValueStart             int    `json:"value_start,string"`
	SequenceNumber         string `json:"sequence_number"`
}

const finalParamsStr = `{
	"CATSin": "4d09468728220770fbac42bd52811a3f9209787d04f410ae006590e7d1c37ced",
	"ECB0": "7a3da051a3a1976df16e6c201e78f67d",
	"ECBK": "bb63f48024f3ba895a6c2fc63e34c013",
	"MSin": "6f9c5634480e08ad8518ea6b0d9f318b7d383e075893423fad6a1637471cb9b4",
	"SATSin": "062853fef9b1b509c06d25fb3a4439234a869cb70b6c62f5195804231027a164",
	"chunk_index": "32",
	"cipher_chunks": "5c15eeb71618a6c33228650be04c1d95bc1c161c5ef289fa5c873c4205c589c4",
	"dHSin": "7a5dc634a969c492cb740f0748ab1282150e8505adec12f4afa18b17094fce90",
	"hashKeyCapp": "3665d1e02e29e90adbf0027ca8dba6b13324c3deda76acebc481bd41945ae015",
	"hashKeySapp": "9a547e148f816797e82e9c93fd2a08b2e7ffcb4666eadc17f58d419cd99efccd",
	"intermediateHashHSopad": "06f1b98bf03282917cc6c783663e03754faa330835fca00a704ba44603b0bdfa",
	"ivCapp": "752e699ccabc4f306cf8efa9",
	"ivSapp": "df770bf453bef01fbcee946f",
	"number_chunks": "2",
	"plain_chunks": "302c353631204575726f227d2c227072696365223a2233383030322e32222c22",
	"size_area_of_interest": "15",
	"size_value": "5",
	"substring": "\"price\"",
	"substring_end": "20",
	"substring_start": "13",
	"substring_start_idx": "493",
	"tkCAPPin": "95a1672108f667ac606f633842bb85ec19a35fb50d10ab2a5721462a1e7d1ada",
	"tkSAPPin": "d46994be330a596b9386ab763c6be3a7e3fb39cf8d667013dc94a5d38a1c474b",
	"value_end": "27",
	"value_start": "22"
}`

const finalParamsStrPayPal = `{
    "CATSin": "7feeb51aaf5290df9ee11466b34bd1e2b4d1f76c8bae5edd33c8d7bc50ff8e11",
    "ECB0": "4fb2cd6ac68eac09fc8592253374fd9c",
    "ECBK": "f83097998164d07e14e54f379e06830d",
    "MSin": "9a7fdc801d51e11fc12ab7ec02c35d77dc49b263558a6f657acde4d2799c818a",
    "SATSin": "cf53c5daac676829982b793d2bec8855cbe3876094b7531d2c8df598154d21e9",
    "chunk_index": "11",
    "cipher_chunks": "e016d41de7a9c8ff41a80433ba1c448b960833d92ddf2b891fc00c32104d8d4a",
    "dHSin": "26fca0cb68ee390496201d365edcef349afc5a050687f6551161275cd6cf9f46",
    "hashKeyCapp": "b5f424203ffe0c4344be022977be5c3ef82c90b2b387b3488e845c153a61e794",
    "hashKeySapp": "d35a840273b5b17ac35dacb2293686f398b7efe5182985ab62c1177ec6d659c2",
    "intermediateHashHSopad": "f83a5836c124d9b06938563d25551b2467a984c79df9602a11db90b2586d039e",
    "ivCapp": "8a454ff6eef00fde322b4b62",
    "ivSapp": "668a9ed2883f5d9c96832f31",
    "number_chunks": "2",
    "plain_chunks": "5344222c2276616c7565223a2233383030322e3230222c22627265616b646f77",
    "size_area_of_interest": "15",
    "size_value": "5",
    "substring": "\"value\"",
    "substring_end": "11",
    "substring_start": "4",
    "substring_start_idx": "148",
    "tkCAPPin": "c57c7da2d84e25a25f1386659253fb6451a0d25f36fe5a95648ad8fe26c20d5f",
    "tkSAPPin": "ccffbb804fdd74d4fd2cfcd01eedfdbd4676f9f3025d75a7c42d63ad38b97478",
    "value_end": "18",
    "value_start": "13"
}`

const finalParamsStrPayPalTest = `{
    "CATSin": "1e7d18d3fabb7f94ebebd9a626047ba74660423cbb039b14ba7e0f28943a3ba8",
    "ECB0": "0656c3ffc0dfc88e748f91b265f02aa1",
    "ECBK": "e22da555fd87c58a50c206501693c446",
    "MSin": "465a8f4e321881c53697568ec08b4dd68d4805dd49f57ae401ffa7a783eaeab3",
    "SATSin": "2af5e21c5aace4b244b52cc2740e8c8cff1beb6806a67fe19b0561467b607e02",
    "chunk_index": "11",
    "cipher_chunks": "0d41589cc274267798b370ced1c39280e582a6dcbcf6954dcd080f66384f71c2",
    "dHSin": "b05eedabe1aade07a5905966e6a8d972f07fcb1084ec56790c8267a1dfc68b7e",
    "hashKeyCapp": "a1826868e38108d1931a5b2c9765baf9c0825ba6cfeee243f6a7478312d76b2c",
    "hashKeySapp": "d8abef557e99ba3b1ff83de3ab9db4e3e2f088a1550207ed7d5c53edff9844e4",
    "intermediateHashHSopad": "93d30a496135af9273352cbf841feb3921e596670888302de006987b67dbccb6",
    "ivCapp": "be9e0432862f2d279dfa7efe",
    "ivSapp": "06c68fe5c03d0953686eab36",
	"sequence_number": "0000000000000001",
    "number_chunks": "2",
    "plain_chunks": "5344222c2276616c7565223a2233383030322e3230222c22627265616b646f77",
    "size_area_of_interest": "15",
    "size_value": "5",
    "substring": "\"value\"",
    "substring_end": "11",
    "substring_start": "4",
    "substring_start_idx": "148",
    "tkCAPPin": "889321f2b107b895e29e1b654ba16b48a289a4c415ce9833b25deca3f6c067b5",
    "tkSAPPin": "561add6266102852f2f1c836eadf93213d4cdee1e482d11b6fefc9e9350a28d0",
    "value_end": "18",
    "value_start": "13"
}`

// Common setup function for both tests
func setupTls13OracleWrapperWrapper() (Tls13OracleWrapper, Tls13OracleWrapper) {

	var data FinalParams
	err := json.Unmarshal([]byte(finalParamsStrPayPalTest), &data)
	if err != nil {
		panic(err)
	}

	intermediateHashHSopad := data.IntermediateHashHSopad
	dHSin := data.DHSin
	MSin := data.MSin
	SATSin := data.SATSin
	tkSAPPin := data.TkSAPPin

	iv := data.IvSapp                           // Assuming the hardcoded 'iv' corresponds to 'ivSapp' from the JSON. / Server side
	zeros := "00000000000000000000000000000000" // This seems to be a constant string not from the JSON.
	ecb0 := data.ECB0
	ecbk := data.ECBK
	cipherChunks := data.CipherChunks
	plainChunks := data.PlainChunks
	chunkIndex := data.ChunkIndex
	substring := data.Substring
	substringStart := data.SubstringStart
	substringEnd := data.SubstringEnd
	valueStart := data.ValueStart
	valueEnd := data.ValueEnd
	sequenceNumber := data.SequenceNumber

	// FIX MANUALLY
	threshold := 38001

	// add counter to iv bytes
	// Value of interest in first record - 1
	// Value of interest in second record - 2
	var sb strings.Builder
	for i := 0; i < len(iv); i++ {
		sb.WriteString(string(iv[i]))
	}
	for i := 0; i < 7; i++ {
		sb.WriteString("0")
	}
	sb.WriteString("2")
	ivCounter := sb.String()

	byteSlice, _ := hex.DecodeString(sequenceNumber)
	sequenceNumberByteLen := len(byteSlice)

	// kdc to bytes
	byteSlice, _ = hex.DecodeString(intermediateHashHSopad)
	intermediateHashHSopadByteLen := len(byteSlice)
	dHSSlice, _ := hex.DecodeString(dHSin)
	dHSinByteLen := len(dHSSlice)
	byteSlice, _ = hex.DecodeString(MSin)
	MSinByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(SATSin)
	SATSinByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(tkSAPPin)
	tkSAPPinByteLen := len(byteSlice)
	// authtag to bytes
	byteSlice, _ = hex.DecodeString(ivCounter)
	ivCounterByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(zeros)
	zerosByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(ecb0)
	ecb0ByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(ecbk)
	ecbkByteLen := len(byteSlice)
	// record to bytes
	byteSlice, _ = hex.DecodeString(iv)
	ivByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(cipherChunks)
	chipherChunksByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(plainChunks)
	plainChunksByteLen := len(byteSlice)
	substringByteLen := len(substring)

	// add padding out of circuit
	pad := utils.PadSha256(96)
	dHSinPadded := make([]byte, 32+len(pad))
	copy(dHSinPadded, dHSSlice)
	copy(dHSinPadded[32:], pad)
	newdHSin := hex.EncodeToString(dHSinPadded)
	dHSinByteLen += 32

	// witness definition kdc
	intermediateHashHSopadAssign := utils.StrToIntSlice(intermediateHashHSopad, true)
	dHSinAssign := utils.StrToIntSlice(newdHSin, true)
	MSinAssign := utils.StrToIntSlice(MSin, true)
	SATSinAssign := utils.StrToIntSlice(SATSin, true)
	tkSAPPinAssign := utils.StrToIntSlice(tkSAPPin, true)
	// witness definition authtag
	ivCounterAssign := utils.StrToIntSlice(ivCounter, true)
	zerosAssign := utils.StrToIntSlice(zeros, true)
	ecb0Assign := utils.StrToIntSlice(ecb0, true)
	ecbkAssign := utils.StrToIntSlice(ecbk, true)
	// witness definition record
	ivAssign := utils.StrToIntSlice(iv, true)
	chipherChunksAssign := utils.StrToIntSlice(cipherChunks, true)
	plainChunksAssign := utils.StrToIntSlice(plainChunks, true)
	substringAssign := utils.StrToIntSlice(substring, false)
	sequenceNumberAssign := utils.StrToIntSlice(sequenceNumber, true)

	// witness values preparation
	assignment := Tls13OracleWrapper{
		// kdc params
		IntermediateHashHSopad: [32]frontend.Variable{},
		DHSin:                  [64]frontend.Variable{},
		MSin:                   [32]frontend.Variable{},
		SATSin:                 [32]frontend.Variable{},
		TkSAPPin:               [32]frontend.Variable{},
		// authtag params
		IvCounter: [16]frontend.Variable{},
		Zeros:     [16]frontend.Variable{},
		ECB0:      [16]frontend.Variable{},
		ECBK:      [16]frontend.Variable{},
		// record pararms
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
		SequenceNumber: [8]frontend.Variable{},
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
	for i := 0; i < SATSinByteLen; i++ {
		assignment.SATSin[i] = SATSinAssign[i]
	}
	for i := 0; i < tkSAPPinByteLen; i++ {
		assignment.TkSAPPin[i] = tkSAPPinAssign[i]
	}
	// authtag assign
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
	// record assign
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
	for i := 0; i < sequenceNumberByteLen; i++ {
		assignment.SequenceNumber[i] = sequenceNumberAssign[i]
	}

	// var circuit kdcServerKey
	circuit := Tls13OracleWrapper{
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
	circuit, assignment := setupTls13OracleWrapperWrapper()

	// Solve the circuit and assert.
	assert.SolvingSucceeded(&circuit, &assignment, test.WithBackends(backend.GROTH16))
}

// Test for Proving
func TestRecordProving(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, assignment := setupTls13OracleWrapperWrapper()

	// Proof successfully generated
	assert.ProverSucceeded(&circuit, &assignment)
}

// Test for Proving with custom serialization
func TestSerializeProving(t *testing.T) {
	// assert := test.NewAssert(t)
	circuit, assignment := setupTls13OracleWrapperWrapper()

	_, err := utils.ProofWithBackend("groth16", false, &circuit, &assignment, ecc.BN254)
	// Proof successfully generated
	if err != nil {
		t.Fatalf("ProofWithBackend failed with error: %v", err)
	}
}
