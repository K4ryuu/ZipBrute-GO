package cracker

import (
	"hash/crc32"
	"testing"
)

// fast path must match plain checkPassword exactly. sweep a keyspace, compare every candidate
func TestFastPathEquivalence(t *testing.T) {
	z := &ZipCryptoChecker{
		crc32Table:   crc32.MakeTable(crc32.IEEE),
		expectedByte: 0x42,
		encHeader:    [12]byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 255, 128},
	}
	table := z.crc32Table
	charset := []byte("abc0")
	length := 5
	csize := len(charset)

	idx := make([]int, length)
	k0 := make([]uint32, length+1)
	k1 := make([]uint32, length+1)
	k2 := make([]uint32, length+1)
	k0[0], k1[0], k2[0] = 305419896, 591751049, 878082192
	recomputeFrom := 0

	pw := make([]byte, length)
	total := 1
	for range length {
		total *= csize
	}

	for i := 0; i < total; i++ {
		for p := recomputeFrom; p < length; p++ {
			ch := charset[idx[p]]
			a0, a1, a2 := k0[p], k1[p], k2[p]
			a0 = table[byte(a0)^ch] ^ (a0 >> 8)
			a1 = (a1+(a0&0xff))*134775813 + 1
			a2 = table[byte(a2)^byte(a1>>24)] ^ (a2 >> 8)
			k0[p+1], k1[p+1], k2[p+1] = a0, a1, a2
		}

		for p := 0; p < length; p++ {
			pw[p] = charset[idx[p]]
		}

		fast := z.checkHeader(k0[length], k1[length], k2[length])
		ref := z.checkPassword(pw)
		if fast != ref {
			t.Fatalf("mismatch at %q: fast=%v ref=%v", pw, fast, ref)
		}

		pos := length - 1
		for pos >= 0 {
			idx[pos]++
			if idx[pos] < csize {
				break
			}
			idx[pos] = 0
			pos--
		}
		if pos < 0 {
			pos = 0
		}
		recomputeFrom = pos
	}
}
