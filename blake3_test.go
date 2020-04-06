package blake3

import (
	"encoding/hex"
	"testing"

	"github.com/zeebo/assert"
	"github.com/zeebo/blake3/internal/consts"
	"github.com/zeebo/blake3/internal/utils"
)

func testHasher(t *testing.T, h hasher, input []byte, hash string) {
	// ensure reset works
	h.update(input[:len(input)/2])
	h.reset()

	// write and finalize a bunch
	var buf [32]byte
	for i := range input {
		h.update(input[i : i+1])
		if i%8193 == 0 {
			h.finalize(buf[:])
		}
	}

	// check every output length requested
	for i := 0; i <= len(hash)/2; i++ {
		buf := make([]byte, i)
		h.finalize(buf)
		assert.Equal(t, hash[:2*i], hex.EncodeToString(buf))
	}
}

func TestVectors_Hash(t *testing.T) {
	for _, tv := range vectors {
		h := hasher{key: consts.IV}
		testHasher(t, h, tv.input(), tv.hash)
	}
}

func TestVectors_KeyedHash(t *testing.T) {
	for _, tv := range vectors {
		h := hasher{flags: consts.Flag_Keyed}
		utils.KeyFromBytes([]byte(testVectorKey), &h.key)
		testHasher(t, h, tv.input(), tv.keyedHash)
	}
}

func TestVectors_DeriveKey(t *testing.T) {
	for _, tv := range vectors {
		// DeriveKey is implemented quite differently from the other
		// modes, it's basically a two-stage hash where the context is
		// hashed into an IV for the "real" hash. At this point, we
		// should have faith in the internal workings of hasher, so
		// test key derivation through the API.
		h, err := DeriveKeySized(testVectorContext, tv.input(), hex.DecodedLen(len(tv.deriveKey)))
		if err != nil {
			t.Fatalf("DeriveKeSized: %v", err)
		}
		derived := h.Sum(nil)
		assert.Equal(t, hex.EncodeToString(derived), tv.deriveKey)
	}
}
