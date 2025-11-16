# ZipBrute-GO

A high-speed ZIP password brute-forcer written in Go. Achieves 120 Million password attempts per second on a typical PC. Passwords up to 6 characters can often be cracked in under 2 seconds, though actual speed depends on charset, password length, and system performance.

## Disclaimer

**Educational purposes only.** Don't use this on ZIPs you don't own.

Only use on your own files or with permission. Unauthorized access is illegal.

## Benchmark

Here are some real benchmarks and results. Tested on my older MacBook with `lower+digits` charset (36 characters in the set):

- **5-character password** (`abc12`): Found in **0.03 seconds**

  - 123.2M checks/sec
  - 4.2M total checks
  - 52.1% required full ZIP validation
  - Workers: 120

- **6-character password** (`abc123`): Found in **0.40 seconds**
  - 145.7M checks/sec
  - 59M total checks
  - 50.1% required full ZIP validation
  - Workers: 120

Actual performance depends on CPU, charset size, and password complexity.

## Features

- Multi-threaded brute force with parallel workers
- Inline hash verification for ZipCrypto (way faster)
- Shared ZIP reader across workers (no re-parsing)
- Batched atomic updates (reduces sync overhead)
- Unsafe pointer casts (zero allocation)
- Local counters (minimizes atomic ops)
- Real-time speed stats
- Customizable charsets and password lengths

## Install

```bash
go get github.com/yeka/zip
./zipcracker.sh build
```

## Usage

Quick:

```bash
./zipcracker.sh run file.zip lower+digits 1 8
```

Direct:

```bash
./zipcracker -f file.zip -c lower+digits -min 4 -max 6
./zipcracker -f file.zip -custom "abc123!@#" -min 1 -max 8
```

## Charset presets

- `digits` - 0-9
- `lower` - a-z
- `upper` - A-Z
- `alpha` - a-zA-Z
- `alnum` - a-zA-Z0-9
- `lower+digits` - a-z0-9 (default)
- `upper+digits` - A-Z0-9
- `all` - everything including symbols

## Flags

- `-f` - zip file path (required)
- `-c` - charset preset (default: lower+digits)
- `-custom` - custom charset string
- `-min` - min password length (default: 1)
- `-max` - max password length (default: 8)
- `-w` - number of workers (default: auto = CPU cores × 10)

## How it works

1. Loads entire ZIP into memory
2. Detects if it's ZipCrypto or AES
3. For ZipCrypto: extracts encrypted header for fast hash checking
4. Spawns worker goroutines to brute force password space
5. Each worker:
   - Generates passwords from index
   - Does fast hash check first (if ZipCrypto)
   - Only tries actual ZIP decompression if hash matches
6. Stops when password found

## Performance

On ZipCrypto files you should see millions of hash checks per second. Only a tiny fraction need actual ZIP validation.

## Notes

- Works best on ZipCrypto (old ZIP encryption)
- AES encrypted ZIPs are slower (no hash optimization)
- Uses unsafe pointer casts for performance
- Batches atomic operations to reduce overhead

## Legal

Again: **Educational purposes only.** I'm not responsible for what you do with this. Use responsibly and legally.

## License

MIT or whatever, just don't be a dick.
