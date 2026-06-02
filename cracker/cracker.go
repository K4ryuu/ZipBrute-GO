package cracker

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/yeka/zip"
)

type ZipCryptoChecker struct {
	encHeader    [12]byte
	crc32Table   *crc32.Table
	expectedByte byte
}

func (z *ZipCryptoChecker) checkPassword(password []byte) bool {
	table := z.crc32Table
	encHeader := z.encHeader
	expectedByte := z.expectedByte

	key0 := uint32(305419896)
	key1 := uint32(591751049)
	key2 := uint32(878082192)

	for i := range password {
		key0 = table[byte(key0)^password[i]] ^ (key0 >> 8)
		key1 = (key1+(key0&0xff))*134775813 + 1
		key2 = table[byte(key2)^byte(key1>>24)] ^ (key2 >> 8)
	}

	for i := range 11 {
		temp := key2 | 2
		c := byte((temp*(temp^1))>>8) ^ encHeader[i]
		key0 = table[byte(key0)^c] ^ (key0 >> 8)
		key1 = (key1+(key0&0xff))*134775813 + 1
		key2 = table[byte(key2)^byte(key1>>24)] ^ (key2 >> 8)
	}

	temp := key2 | 2
	c := byte((temp*(temp^1))>>8) ^ encHeader[11]
	return c == expectedByte
}

// runs the 12-byte header check from key state already advanced past the password.
// lets us cache the password key schedule across candidates instead of redoing it every time
func (z *ZipCryptoChecker) checkHeader(key0, key1, key2 uint32) bool {
	table := z.crc32Table
	encHeader := z.encHeader

	for i := range 11 {
		temp := key2 | 2
		c := byte((temp*(temp^1))>>8) ^ encHeader[i]
		key0 = table[byte(key0)^c] ^ (key0 >> 8)
		key1 = (key1+(key0&0xff))*134775813 + 1
		key2 = table[byte(key2)^byte(key1>>24)] ^ (key2 >> 8)
	}

	temp := key2 | 2
	c := byte((temp*(temp^1))>>8) ^ encHeader[11]
	return c == z.expectedByte
}

type Cracker struct {
	zipPath      string
	zipData      []byte
	fileIndex    int
	charset      []byte
	minLen       int
	maxLen       int
	workers      int
	startTime    time.Time
	cryptoCheck  *ZipCryptoChecker
	useHashCheck bool

	attempts  uint64
	checked   uint64
	found     atomic.Bool
	result    string
	resultMux sync.Mutex
}

// new cracker. charset, length range, worker count
func New(charset []byte, minLen, maxLen, workers int) *Cracker {
	return &Cracker{
		charset: charset,
		minLen:  minLen,
		maxLen:  maxLen,
		workers: workers,
	}
}

// true when the ZipCrypto shortcut is on (skip full decrypt)
func (c *Cracker) FastMode() bool { return c.useHashCheck }

// current worker count
func (c *Cracker) Workers() int { return c.workers }

type workerContext struct {
	zipReader *zip.Reader
	file      *zip.File
}

func (c *Cracker) newWorkerContext() (*workerContext, error) {
	// each worker gets its own zip.Reader, sharing one isn't thread-safe
	r, err := zip.NewReader(bytes.NewReader(c.zipData), int64(len(c.zipData)))
	if err != nil {
		return nil, err
	}

	if c.fileIndex >= len(r.File) {
		return nil, fmt.Errorf("target file index out of range")
	}

	return &workerContext{
		zipReader: r,
		file:      r.File[c.fileIndex],
	}, nil
}

func (ctx *workerContext) tryPassword(password []byte) bool {
	ctx.file.SetPassword(*(*string)(unsafe.Pointer(&password)))

	reader, err := ctx.file.Open()
	if err != nil {
		return false
	}
	defer reader.Close()

	_, err = io.Copy(io.Discard, reader)
	return err == nil
}

func (c *Cracker) rangeWorker(start, end uint64, length int, wg *sync.WaitGroup) {
	defer wg.Done()

	ctx, err := c.newWorkerContext()
	if err != nil {
		return
	}

	charsetSize := uint64(len(c.charset))
	password := make([]byte, length)
	localAttempts := uint64(0)
	localChecked := uint64(0)

	for i := start; i < end && !c.found.Load(); i++ {
		num := i
		for pos := length - 1; pos >= 0; pos-- {
			password[pos] = c.charset[num%charsetSize]
			num /= charsetSize
		}

		localChecked++
		localAttempts++
		if ctx.tryPassword(password) {
			c.found.Store(true)
			c.resultMux.Lock()
			c.result = string(password)
			c.resultMux.Unlock()

			atomic.AddUint64(&c.attempts, localAttempts)
			atomic.AddUint64(&c.checked, localChecked)
			return
		}

		if localAttempts%1000 == 0 {
			atomic.AddUint64(&c.attempts, 1000)
			atomic.AddUint64(&c.checked, localChecked)
			localAttempts = 0
			localChecked = 0
		}
	}

	atomic.AddUint64(&c.attempts, localAttempts)
	atomic.AddUint64(&c.checked, localChecked)
}

// pick the right worker for the range: prefix-cached fast path for ZipCrypto,
// plain open-every-candidate for AES
func (c *Cracker) spawnWorker(start, end uint64, length int, wg *sync.WaitGroup) {
	if c.useHashCheck && c.cryptoCheck != nil {
		go c.rangeWorkerFast(start, end, length, wg)
	} else {
		go c.rangeWorker(start, end, length, wg)
	}
}

// brute-force a ZipCrypto range. caches the CRC key state per password prefix and
// only re-derives from the lowest digit that changed. header check (12 bytes) still
// runs every candidate, but the password key schedule gets mostly reused.
// only opens the zip on a header hit (rare), so the reader is built lazily
func (c *Cracker) rangeWorkerFast(start, end uint64, length int, wg *sync.WaitGroup) {
	defer wg.Done()

	z := c.cryptoCheck
	table := z.crc32Table
	charset := c.charset
	csize := len(charset)

	var ctx *workerContext // built on first header hit

	// odometer digits (charset indices), idx[0] = most significant
	idx := make([]int, length)
	num := start
	for pos := length - 1; pos >= 0; pos-- {
		idx[pos] = int(num % uint64(csize))
		num /= uint64(csize)
	}

	// k*[p] = key state after processing digits idx[0..p-1]
	k0 := make([]uint32, length+1)
	k1 := make([]uint32, length+1)
	k2 := make([]uint32, length+1)
	k0[0], k1[0], k2[0] = 305419896, 591751049, 878082192
	recomputeFrom := 0

	password := make([]byte, length)
	localChecked := uint64(0)

	flush := func() {
		atomic.AddUint64(&c.checked, localChecked)
		atomic.AddUint64(&c.attempts, localChecked)
		localChecked = 0
	}

	for i := start; i < end && !c.found.Load(); i++ {
		for p := recomputeFrom; p < length; p++ {
			ch := charset[idx[p]]
			a0, a1, a2 := k0[p], k1[p], k2[p]
			a0 = table[byte(a0)^ch] ^ (a0 >> 8)
			a1 = (a1+(a0&0xff))*134775813 + 1
			a2 = table[byte(a2)^byte(a1>>24)] ^ (a2 >> 8)
			k0[p+1], k1[p+1], k2[p+1] = a0, a1, a2
		}

		localChecked++

		if z.checkHeader(k0[length], k1[length], k2[length]) {
			for p := 0; p < length; p++ {
				password[p] = charset[idx[p]]
			}
			if ctx == nil {
				var err error
				if ctx, err = c.newWorkerContext(); err != nil {
					flush()
					return
				}
			}
			if ctx.tryPassword(password) {
				c.found.Store(true)
				c.resultMux.Lock()
				c.result = string(password)
				c.resultMux.Unlock()
				flush()
				return
			}
		}

		if localChecked >= 4096 {
			flush()
		}

		// odometer++, recompute from the digit that changed
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
			pos = 0 // wrapped past the end; loop exits next check
		}
		recomputeFrom = pos
	}

	flush()
}

func (c *Cracker) monitor(stop <-chan bool) {
	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()

	lastChecked := uint64(0)
	lastTime := time.Now()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if c.found.Load() {
				return
			}

			checked := atomic.LoadUint64(&c.checked)
			attempts := atomic.LoadUint64(&c.attempts)
			elapsed := time.Since(c.startTime).Seconds()

			now := time.Now()
			timeDelta := now.Sub(lastTime).Seconds()
			checkedDelta := checked - lastChecked
			instantSpeed := float64(checkedDelta) / timeDelta

			avgSpeed := float64(checked) / elapsed
			if elapsed < 0.01 {
				avgSpeed = 0
				instantSpeed = 0
			}

			hashRatio := float64(0)
			if checked > 0 {
				hashRatio = float64(attempts) / float64(checked) * 100
			}

			fmt.Printf("\r[*] %d checks | %.1fM/s avg | %.1fM/s | %.1f%% zip attempts | %.1fs     ",
				checked, avgSpeed/1000000, instantSpeed/1000000, hashRatio, elapsed)

			lastChecked = checked
			lastTime = now
		}
	}
}

// map a preset name to its chars, or just use the arg as a literal charset
func GetCharset(preset string) []byte {
	charsets := map[string]string{
		"digits":       "0123456789",
		"lower":        "abcdefghijklmnopqrstuvwxyz",
		"upper":        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"alpha":        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"alnum":        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		"lower+digits": "abcdefghijklmnopqrstuvwxyz0123456789",
		"upper+digits": "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		"all":          "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?",
	}

	if charset, ok := charsets[preset]; ok {
		return []byte(charset)
	}
	return []byte(preset)
}

func (c *Cracker) calculateTotal(length int) uint64 {
	total := uint64(1)
	charsetSize := uint64(len(c.charset))
	for range length {
		total *= charsetSize
	}
	return total
}

// grab first entry that's actually encrypted + not a folder.
// File[0] alone is a trap: if zip starts with a dir/plain file, Open() says yes to any password
func selectTargetFile(r *zip.Reader) (int, error) {
	for i, f := range r.File {
		if f.IsEncrypted() && !f.FileInfo().IsDir() {
			return i, nil
		}
	}
	return 0, fmt.Errorf("no encrypted file found in archive")
}

// AES = winzip extra field 0x9901. no field → plain old ZipCrypto
func isAES(f *zip.File) bool {
	extra := f.Extra
	for len(extra) >= 4 {
		id := binary.LittleEndian.Uint16(extra[0:2])
		size := int(binary.LittleEndian.Uint16(extra[2:4]))
		if id == 0x9901 {
			return true
		}
		if 4+size > len(extra) {
			break
		}
		extra = extra[4+size:]
	}
	return false
}

// pull the 12-byte ZipCrypto header + figure out the verify byte.
// normally it's high byte of CRC32, but streaming entries (data descriptor) use mod-time instead
func buildZipCryptoChecker(zipData []byte, f *zip.File) (*ZipCryptoChecker, error) {
	off, err := f.DataOffset()
	if err != nil {
		return nil, err
	}
	if int(off)+12 > len(zipData) {
		return nil, fmt.Errorf("truncated zip: encryption header out of range")
	}

	var expected byte
	if f.Flags&0x8 != 0 {
		expected = byte(f.ModifiedTime >> 8)
	} else {
		expected = byte(f.CRC32 >> 24)
	}

	checker := &ZipCryptoChecker{
		crc32Table:   crc32.MakeTable(crc32.IEEE),
		expectedByte: expected,
	}
	copy(checker.encHeader[:], zipData[off:off+12])
	return checker, nil
}

// bench a few worker counts, keep the fastest
func (c *Cracker) AutoTune(testDuration time.Duration) int {
	candidates := []int{300, 500, 800, 1000, 1200}
	bestWorkers := 1000
	bestSpeed := 0.0

	fmt.Printf("[*] Auto-tuning worker count (testing %d candidates)...\n", len(candidates))

	for _, workerCount := range candidates {
		c.workers = workerCount
		c.attempts = 0
		c.checked = 0
		c.found.Store(false)
		c.startTime = time.Now()

		var wg sync.WaitGroup
		done := make(chan bool)

		// need enough work to bench, so at least length 8
		testLen := c.minLen
		if testLen < 8 {
			testLen = 8
		}

		testTotal := c.calculateTotal(testLen)
		testChunk := testTotal / uint64(workerCount)
		if testChunk == 0 {
			testChunk = 1
		}

		for i := 0; i < workerCount; i++ {
			start := uint64(i) * testChunk
			end := min(start+testChunk, testTotal)
			wg.Add(1)
			c.spawnWorker(start, end, testLen, &wg)
		}

		go func() {
			time.Sleep(testDuration)
			c.found.Store(true)
			done <- true
		}()

		<-done
		wg.Wait()

		elapsed := time.Since(c.startTime).Seconds()
		checked := atomic.LoadUint64(&c.checked)
		speed := float64(checked) / elapsed

		fmt.Printf("  [%4d workers] %.1f M/s\n", workerCount, speed/1000000)

		if speed > bestSpeed {
			bestSpeed = speed
			bestWorkers = workerCount
		}
	}

	fmt.Printf("[+] Optimal worker count: %d (%.1f M/s)\n\n", bestWorkers, bestSpeed/1000000)

	c.found.Store(false)
	c.attempts = 0
	c.checked = 0
	c.workers = bestWorkers

	return bestWorkers
}

// read the zip off disk and prep the cracker
func (c *Cracker) LoadFile(path string) error {
	c.zipPath = path
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return c.InitFromData(data)
}

// prep from raw zip bytes: pick the target encrypted entry, wire up the
// ZipCrypto fast-path if it applies
func (c *Cracker) InitFromData(data []byte) error {
	c.zipData = data

	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}

	idx, err := selectTargetFile(r)
	if err != nil {
		return err
	}
	c.fileIndex = idx
	target := r.File[idx]

	if isAES(target) {
		c.useHashCheck = false
		fmt.Printf("[+] AES encryption detected\n")
		return nil
	}

	checker, err := buildZipCryptoChecker(data, target)
	if err != nil {
		return err
	}
	c.cryptoCheck = checker
	c.useHashCheck = true
	fmt.Printf("[+] ZipCrypto detected - fast mode enabled\n")
	return nil
}

// run the brute-force, return the pw if we crack it
func (c *Cracker) Crack() (string, bool) {
	c.startTime = time.Now()

	stopMonitor := make(chan bool)
	go c.monitor(stopMonitor)
	defer close(stopMonitor)

	fmt.Printf("\n[*] file: %d KB | charset: %d | length: %d-%d | workers: %d\n",
		len(c.zipData)/1024, len(c.charset), c.minLen, c.maxLen, c.workers)

	for length := c.minLen; length <= c.maxLen; length++ {
		if c.found.Load() {
			break
		}

		total := c.calculateTotal(length)
		fmt.Printf("\n[*] length %d (%d combinations)\n", length, total)

		chunkSize := total / uint64(c.workers)
		if chunkSize == 0 {
			chunkSize = 1
		}

		var wg sync.WaitGroup

		for i := 0; i < c.workers; i++ {
			start := uint64(i) * chunkSize
			end := start + chunkSize
			if i == c.workers-1 {
				end = total
			}

			if start >= total {
				break
			}

			wg.Add(1)
			c.spawnWorker(start, end, length, &wg)
		}

		wg.Wait()

		if c.found.Load() {
			break
		}
	}

	stopMonitor <- true

	if c.found.Load() {
		elapsed := time.Since(c.startTime)
		checked := atomic.LoadUint64(&c.checked)
		attempts := atomic.LoadUint64(&c.attempts)
		avgSpeed := float64(checked) / elapsed.Seconds()

		hashRatio := float64(0)
		if checked > 0 {
			hashRatio = float64(attempts) / float64(checked) * 100
		}

		fmt.Printf("\n\n[+] PASSWORD FOUND: '%s'\n", c.result)
		fmt.Printf("[*] time: %.2fs | checks: %d | attempts: %d (%.1f%%) | speed: %.1fM/s\n",
			elapsed.Seconds(), checked, attempts, hashRatio, avgSpeed/1000000)
		return c.result, true
	}

	fmt.Printf("\n[-] no match found\n")
	return "", false
}
