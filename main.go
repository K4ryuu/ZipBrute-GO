package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"zipcracker/cracker"
)

func usage() {
	const help = `ZipBrute-GO  -  fast ZIP password brute-forcer (ZipCrypto + AES)

USAGE
  zipcracker -f <file.zip> [options]

OPTIONS
  -f <path>        zip file to crack (required)
  -c <preset>      charset preset (default: lower+digits)
  -custom <chars>  custom charset, overrides -c   e.g. -custom "abc123!"
  -min <n>         min password length (default: 1)
  -max <n>         max password length (default: 32)
  -w <n>           worker count (default: auto, NumCPU x10)
  -auto            benchmark worker counts at startup, use the fastest

CHARSET PRESETS
  digits         0-9
  lower          a-z
  upper          A-Z
  alpha          a-z A-Z
  alnum          a-z A-Z 0-9
  lower+digits   a-z 0-9
  upper+digits   A-Z 0-9
  all            a-z A-Z 0-9 + symbols

EXAMPLES
  zipcracker -f secret.zip -c digits -max 6
  zipcracker -f secret.zip -custom "abcABC123" -min 4 -max 8
  zipcracker -f secret.zip -auto
`
	fmt.Fprint(os.Stderr, help)
}

func main() {
	zipPath := flag.String("f", "", "zip file path")
	charset := flag.String("c", "lower+digits", "charset preset (digits, lower, upper, alpha, alnum, lower+digits, upper+digits, all)")
	customCharset := flag.String("custom", "", "custom charset string")
	minLen := flag.Int("min", 1, "min password length")
	maxLen := flag.Int("max", 32, "max password length")
	workers := flag.Int("w", 0, "number of workers (0 = auto)")
	autoTune := flag.Bool("auto", false, "auto-tune optimal worker count at startup")

	flag.Usage = usage
	flag.Parse()

	if *zipPath == "" {
		usage()
		os.Exit(1)
	}

	if _, err := os.Stat(*zipPath); os.IsNotExist(err) {
		fmt.Printf("[-] file not found: %s\n", *zipPath)
		os.Exit(1)
	}

	if *workers == 0 {
		*workers = runtime.NumCPU() * 10
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	var finalCharset []byte
	if *customCharset != "" {
		finalCharset = []byte(*customCharset)
	} else {
		finalCharset = cracker.GetCharset(*charset)
	}

	c := cracker.New(finalCharset, *minLen, *maxLen, *workers)

	if err := c.LoadFile(*zipPath); err != nil {
		fmt.Printf("[-] error loading zip: %v\n", err)
		os.Exit(1)
	}

	if *autoTune {
		c.AutoTune(2 * time.Second)
	}

	c.Crack()
}
