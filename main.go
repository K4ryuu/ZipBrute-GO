package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"runtime"
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

	// byte 11 check
	temp := key2 | 2
	c := byte((temp*(temp^1))>>8) ^ encHeader[11]
	return c == expectedByte
}

type Cracker struct {
	zipPath         string
	zipData         []byte
	charset         []byte
	minLen          int
	maxLen          int
	workers         int
	attempts        uint64
	checked         uint64
	startTime       time.Time
	found           atomic.Bool
	result          string
	resultMux       sync.Mutex
	cryptoCheck     *ZipCryptoChecker
	useHashCheck    bool
	globalZipReader *zip.Reader
	readerMux       sync.Mutex
}

type workerContext struct {
	file *zip.File
}

func (c *Cracker) newWorkerContext() (*workerContext, error) {
	c.readerMux.Lock()
	defer c.readerMux.Unlock()

	if c.globalZipReader == nil {
		r, err := zip.NewReader(bytes.NewReader(c.zipData), int64(len(c.zipData)))
		if err != nil {
			return nil, err
		}
		c.globalZipReader = r
	}

	if len(c.globalZipReader.File) == 0 {
		return nil, fmt.Errorf("empty zip")
	}

	return &workerContext{
		file: c.globalZipReader.File[0],
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

		if c.useHashCheck && c.cryptoCheck != nil {
			if !c.cryptoCheck.checkPassword(password) {
				localAttempts++
				if localAttempts%1000 == 0 {
					atomic.AddUint64(&c.attempts, 1000)
					atomic.AddUint64(&c.checked, 1000)
					localAttempts = 0
				}
				continue
			}
		}

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

func getCharset(preset string) []byte {
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

func extractVerificationBytes(zipData []byte) (*ZipCryptoChecker, bool) {
	if len(zipData) < 100 {
		return nil, false
	}

	if zipData[0] != 'P' || zipData[1] != 'K' {
		return nil, false
	}

	flags := binary.LittleEndian.Uint16(zipData[6:8])
	encrypted := (flags & 0x1) != 0
	strongEncrypt := (flags & 0x40) != 0

	if !encrypted || strongEncrypt {
		return nil, false
	}

	modTime := binary.LittleEndian.Uint16(zipData[10:12])

	fnameLen := binary.LittleEndian.Uint16(zipData[26:28])
	extraLen := binary.LittleEndian.Uint16(zipData[28:30])

	headerStart := 30 + int(fnameLen) + int(extraLen)

	if len(zipData) < headerStart+12 {
		return nil, false
	}

	checker := &ZipCryptoChecker{
		crc32Table:   crc32.MakeTable(crc32.IEEE),
		expectedByte: byte((modTime >> 8) & 0xFF),
	}

	copy(checker.encHeader[:], zipData[headerStart:headerStart+12])

	return checker, true
}

func (c *Cracker) crack() (string, bool) {
	c.startTime = time.Now()

	data, err := os.ReadFile(c.zipPath)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return "", false
	}
	c.zipData = data

	checker, isZipCrypto := extractVerificationBytes(data)
	if isZipCrypto {
		c.cryptoCheck = checker
		c.useHashCheck = true
		fmt.Printf("[+] ZipCrypto detected - fast mode enabled\n")
	} else {
		c.useHashCheck = false
		fmt.Printf("[+] AES encryption detected\n")
	}

	stopMonitor := make(chan bool)
	go c.monitor(stopMonitor)
	defer close(stopMonitor)

	fmt.Printf("\n[*] file: %d KB | charset: %d | length: %d-%d | workers: %d\n",
		len(data)/1024, len(c.charset), c.minLen, c.maxLen, c.workers)

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
			go c.rangeWorker(start, end, length, &wg)
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

func main() {
	zipPath := flag.String("f", "", "zip file path")
	charset := flag.String("c", "lower+digits", "charset preset (digits, lower, upper, alpha, alnum, lower+digits, upper+digits, all)")
	customCharset := flag.String("custom", "", "custom charset string")
	minLen := flag.Int("min", 1, "min password length")
	maxLen := flag.Int("max", 32, "max password length")
	workers := flag.Int("w", 0, "number of workers (0 = auto)")

	flag.Parse()

	if *zipPath == "" {
		fmt.Println("usage: ./zipcracker -f file.zip -c lower+digits -min 1 -max 8")
		fmt.Println("\ncharsets: digits, lower, upper, alpha, alnum, lower+digits, upper+digits, all")
		fmt.Println("or use: -custom \"abc123\"")
		os.Exit(1)
	}

	if _, err := os.Stat(*zipPath); os.IsNotExist(err) {
		fmt.Printf("[-] file not found: %s\n", *zipPath)
		os.Exit(1)
	}

	if *workers == 0 {
		*workers = min(runtime.NumCPU()*10, 200)
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	var finalCharset []byte
	if *customCharset != "" {
		finalCharset = []byte(*customCharset)
	} else {
		finalCharset = getCharset(*charset)
	}

	cracker := &Cracker{
		zipPath: *zipPath,
		charset: finalCharset,
		minLen:  *minLen,
		maxLen:  *maxLen,
		workers: *workers,
	}

	cracker.crack()
}
