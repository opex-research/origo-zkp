package utils

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/montanaflynn/stats"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

// non-gnark padding function
func PadSha256(len uint64) []byte {
	var tmp [64 + 8]byte // padding + length buffer
	tmp[0] = 0x80
	var t uint64
	if len%64 < 56 {
		t = 56 - len%64
	} else {
		t = 64 + 56 - len%64
	}

	// Length in bits.
	len <<= 3
	padlen := tmp[:t+8]
	binary.BigEndian.PutUint64(padlen[t+0:], len)
	return padlen
}

// non-gnark str to int conversion
func StrToIntSlice(inputData string, hexRepresentation bool) []int {

	// check if inputData in hex representation
	var byteSlice []byte
	if hexRepresentation {
		hexBytes, err := hex.DecodeString(inputData)
		if err != nil {
			log.Error().Msg("hex.DecodeString error.")
		}
		byteSlice = hexBytes
	} else {
		byteSlice = []byte(inputData)
	}

	// convert byte slice to int numbers which can be passed to gnark frontend.Variable
	var data []int
	for i := 0; i < len(byteSlice); i++ {
		data = append(data, int(byteSlice[i]))
	}

	return data
}

func StoreM(jsonData map[string]string, path string, filename string) error {

	file, err := json.MarshalIndent(jsonData, "", " ")
	if err != nil {
		log.Error().Err(err).Msg("json.MarshalIndent")
		return err
	}
	err = os.WriteFile(path+filename+".json", file, 0644)
	if err != nil {
		log.Error().Err(err).Msg("os.WriteFile")
		return err
	}
	return nil
}

func AddStats(data map[string]string, results []map[string]time.Duration, print2console bool) {

	// default type expected by github.com/montanaflynn/stats package
	aggrCompile := []float64{}
	aggrSetup := []float64{}
	aggrProve := []float64{}
	aggrVerify := []float64{}
	// aggregate times
	for _, mapData := range results {
		// convert all numbers to seconds as the base, take time.Milisecond if ms required
		aggrCompile = append(aggrCompile, float64(mapData["compile"].Seconds()))
		aggrSetup = append(aggrSetup, float64(mapData["setup"].Seconds()))
		aggrProve = append(aggrProve, float64(mapData["prove"].Seconds()))
		aggrVerify = append(aggrVerify, float64(mapData["verify"].Seconds()))
	}

	// check print to console
	if print2console {
		fmt.Println("compile times:", aggrCompile)
		fmt.Println("setup times:", aggrSetup)
		fmt.Println("prove times:", aggrProve)
		fmt.Println("verify times:", aggrVerify)
	}

	// adding stats
	// statistics api here https://pkg.go.dev/github.com/montanaflynn/stats#section-readme
	// float conversion options here https://yourbasic.org/golang/convert-string-to-float/
	// med, _ := stats.Median(aggrCompile)
	mean, _ := stats.Mean(aggrCompile)
	std, _ := stats.StandardDeviation(aggrCompile)
	// data["time_compile_median"] = fmt.Sprintf("%.3f", med)
	data["time_compile_mean"] = fmt.Sprintf("%.3f", mean)
	data["time_compile_standard_deviation"] = fmt.Sprintf("%.3f", std)

	// med, _ = stats.Median(aggrSetup)
	mean, _ = stats.Mean(aggrSetup)
	std, _ = stats.StandardDeviation(aggrSetup)
	// data["time_setup_median"] = fmt.Sprintf("%.3f", med)
	data["time_setup_mean"] = fmt.Sprintf("%.3f", mean)
	data["time_setup_standard_deviation"] = fmt.Sprintf("%.3f", std)

	// med, _ = stats.Median(aggrProve)
	mean, _ = stats.Mean(aggrProve)
	std, _ = stats.StandardDeviation(aggrProve)
	// data["time_prove_median"] = fmt.Sprintf("%.3f", med)
	data["time_prove_mean"] = fmt.Sprintf("%.3f", mean)
	data["time_prove_standard_deviation"] = fmt.Sprintf("%.3f", std)

	// med, _ = stats.Median(aggrVerify)
	mean, _ = stats.Mean(aggrVerify)
	std, _ = stats.StandardDeviation(aggrVerify)
	// data["time_verify_median"] = fmt.Sprintf("%.3f", med)
	data["time_verify_mean"] = fmt.Sprintf("%.3f", mean)
	data["time_verify_standard_deviation"] = fmt.Sprintf("%.3f", std)
}

// compressThreshold --> if linear expressions are larger than this, the frontend will introduce
// intermediate constraints. The lower this number is, the faster compile time should be (to a point)
// but resulting circuit will have more constraints (slower proving time).
// const compressThreshold = 1000

func BenchProof(b *testing.B, circuit, assignment frontend.Circuit) {
	fmt.Println("compiling...")
	start := time.Now().UnixMicro()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit) //, frontend.WithCompressThreshold(compressThreshold))
	require.NoError(b, err)
	fmt.Println("compiled in", time.Now().UnixMicro()-start, "μs")
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	require.NoError(b, err)
	//publicWitness := fullWitness.Public()
	fmt.Println("setting up...")
	pk, _, err := groth16.Setup(cs)
	require.NoError(b, err)

	fmt.Println("solving and proving...")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		id := rand.Uint32() % 256 //#nosec G404 -- This is a false positive
		start = time.Now().UnixMicro()
		fmt.Println("groth16 proving", id)
		_, err = groth16.Prove(cs, pk, fullWitness)
		require.NoError(b, err)
		fmt.Println("groth16 proved", id, "in", time.Now().UnixMicro()-start, "μs")

		// fmt.Println("mimc total calls: fr=", mimcFrTotalCalls, ", snark=", mimcSnarkTotalCalls)
	}
}
