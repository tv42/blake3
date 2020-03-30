package avx2

import (
	"testing"

	"github.com/zeebo/assert"
	"github.com/zeebo/blake3/ref"
	"github.com/zeebo/pcg"
)

func TestHashF(t *testing.T) {
	var input [8192]byte
	var key [8]uint32

	for n := 0; n <= 8192; n++ {
		var c1, c2 [8]uint32
		var o1, o2 [64]uint32

		ctr, flags := pcg.Uint64(), pcg.Uint32()
		for i := range &key {
			key[i] = pcg.Uint32()
		}
		for i := 0; i < n; i++ {
			input[i] = byte(i+1) % 251
		}

		HashF(&input, uint64(n), ctr, flags, &key, &o1, &c1)
		ref.HashF(&input, uint64(n), ctr, flags, &key, &o2, &c2)

		for i := 0; (i+1)*1024 <= n; i++ {
			for j := 0; j < 8; j++ {
				assert.Equal(t, o1[i+8*j], o2[i+8*j])
			}
		}
		if n%1024 != 0 {
			assert.Equal(t, c1, c2)
		}
	}
}

func TestHashP(t *testing.T) {
	var key [8]uint32
	var left, right [64]uint32

	for i := 0; i < 64; i++ {
		left[i] = uint32(i+1) % 251
		right[i] = uint32(i+2) % 251
	}

	for n := 1; n <= 8; n++ {
		var o1, o2 [64]uint32

		for i := range &key {
			key[i] = pcg.Uint32()
		}

		HashP(&left, &right, 0, &key, &o1, n)
		ref.HashP(&left, &right, 0, &key, &o2, n)

		for i := 0; i < n; i++ {
			for j := 0; j < 8; j++ {
				assert.Equal(t, o1[i+8*j], o2[i+8*j])
			}
		}
	}
}
