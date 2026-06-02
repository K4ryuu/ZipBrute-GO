package cracker

import (
	"hash/crc32"
	"testing"
)

func benchChecker() *ZipCryptoChecker {
	return &ZipCryptoChecker{
		crc32Table:   crc32.MakeTable(crc32.IEEE),
		expectedByte: 0x42,
		encHeader:    [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
	}
}

// sweep a length-6 keyspace like rangeWorker does (odometer fill),
// so the bench matches the real consecutive-candidate pattern
func BenchmarkCheckPassword(b *testing.B) {
	z := benchChecker()
	charset := []byte("abcdefghijklmnopqrstuvwxyz0123456789")
	length := 6
	csize := uint64(len(charset))
	pw := make([]byte, length)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		num := uint64(i)
		for pos := length - 1; pos >= 0; pos-- {
			pw[pos] = charset[num%csize]
			num /= csize
		}
		z.checkPassword(pw)
	}
}

// prefix-cached sweep: only re-derive key state from the lowest digit that changed
func BenchmarkCheckPasswordIncremental(b *testing.B) {
	z := benchChecker()
	table := z.crc32Table
	charset := []byte("abcdefghijklmnopqrstuvwxyz0123456789")
	length := 6
	csize := len(charset)

	idx := make([]int, length)
	k0 := make([]uint32, length+1)
	k1 := make([]uint32, length+1)
	k2 := make([]uint32, length+1)
	k0[0], k1[0], k2[0] = 305419896, 591751049, 878082192
	recomputeFrom := 0

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for p := recomputeFrom; p < length; p++ {
			ch := charset[idx[p]]
			a0, a1, a2 := k0[p], k1[p], k2[p]
			a0 = table[byte(a0)^ch] ^ (a0 >> 8)
			a1 = (a1+(a0&0xff))*134775813 + 1
			a2 = table[byte(a2)^byte(a1>>24)] ^ (a2 >> 8)
			k0[p+1], k1[p+1], k2[p+1] = a0, a1, a2
		}
		z.checkHeader(k0[length], k1[length], k2[length])

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
