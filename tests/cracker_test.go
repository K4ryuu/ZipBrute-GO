package tests

import (
	"bytes"
	"io"
	"testing"

	"github.com/yeka/zip"

	"zipcracker/cracker"
)

// --- test fixtures -----------------------------------------------------------

type entry struct {
	name     string
	content  string
	password string // "" = unencrypted
	enc      zip.EncryptionMethod
	isDir    bool
}

func makeZip(t *testing.T, entries []entry) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	for _, e := range entries {
		switch {
		case e.isDir:
			if _, err := zw.Create(e.name); err != nil { // trailing slash → dir
				t.Fatalf("create dir %s: %v", e.name, err)
			}
		case e.password != "":
			w, err := zw.Encrypt(e.name, e.password, e.enc)
			if err != nil {
				t.Fatalf("encrypt %s: %v", e.name, err)
			}
			if _, err := io.WriteString(w, e.content); err != nil {
				t.Fatalf("write %s: %v", e.name, err)
			}
		default:
			w, err := zw.Create(e.name)
			if err != nil {
				t.Fatalf("create %s: %v", e.name, err)
			}
			if _, err := io.WriteString(w, e.content); err != nil {
				t.Fatalf("write %s: %v", e.name, err)
			}
		}
	}

	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

func newCracker(t *testing.T, data []byte, charset string, min, max int) *cracker.Cracker {
	t.Helper()
	c := cracker.New([]byte(charset), min, max, 4)
	if err := c.InitFromData(data); err != nil {
		t.Fatalf("InitFromData: %v", err)
	}
	return c
}

// --- charset -----------------------------------------------------------------

func TestGetCharset(t *testing.T) {
	tests := map[string]string{
		"digits":       "0123456789",
		"lower":        "abcdefghijklmnopqrstuvwxyz",
		"lower+digits": "abcdefghijklmnopqrstuvwxyz0123456789",
	}
	for preset, want := range tests {
		if got := string(cracker.GetCharset(preset)); got != want {
			t.Errorf("GetCharset(%q) = %q, want %q", preset, got, want)
		}
	}
	// unknown preset → treated as a literal charset
	if got := string(cracker.GetCharset("xyz")); got != "xyz" {
		t.Errorf("GetCharset fallback = %q, want %q", got, "xyz")
	}
}

// --- encryption detection ----------------------------------------------------

func TestInitFromData_DetectsZipCrypto(t *testing.T) {
	c := newCracker(t, makeZip(t, []entry{
		{name: "a.txt", content: "x", password: "p", enc: zip.StandardEncryption},
	}), "p", 1, 1)
	if !c.FastMode() {
		t.Error("ZipCrypto should enable fast mode")
	}
}

func TestInitFromData_DetectsAES(t *testing.T) {
	c := newCracker(t, makeZip(t, []entry{
		{name: "a.txt", content: "x", password: "p", enc: zip.AES256Encryption},
	}), "p", 1, 1)
	if c.FastMode() {
		t.Error("AES should not enable the ZipCrypto fast mode")
	}
}

func TestInitFromData_NoEncryptedFile(t *testing.T) {
	c := cracker.New([]byte("ab"), 1, 2, 4)
	err := c.InitFromData(makeZip(t, []entry{{name: "readme.txt", content: "plain"}}))
	if err == nil {
		t.Error("expected error when archive has no encrypted file")
	}
}

// --- end-to-end crack --------------------------------------------------------

func TestCrack_ZipCrypto(t *testing.T) {
	data := makeZip(t, []entry{{name: "a.txt", content: "hello world", password: "xy", enc: zip.StandardEncryption}})
	if got, ok := newCracker(t, data, "xyz", 1, 2).Crack(); !ok || got != "xy" {
		t.Errorf("Crack = (%q, %v), want (xy, true)", got, ok)
	}
}

func TestCrack_AES(t *testing.T) {
	data := makeZip(t, []entry{{name: "a.txt", content: "hello world", password: "xy", enc: zip.AES256Encryption}})
	if got, ok := newCracker(t, data, "xyz", 1, 2).Crack(); !ok || got != "xy" {
		t.Errorf("Crack = (%q, %v), want (xy, true)", got, ok)
	}
}

func TestCrack_NotFound(t *testing.T) {
	data := makeZip(t, []entry{{name: "a.txt", content: "x", password: "zz", enc: zip.AES256Encryption}})
	if got, ok := newCracker(t, data, "ab", 1, 2).Crack(); ok { // "zz" not reachable
		t.Errorf("Crack = %q, want no match", got)
	}
}

// --- issue #2 regressions ----------------------------------------------------
// zip starting with a dir/plain entry must not fake a hit, and must still find the real pw.

func TestCrack_Regression_DirFirst_AES(t *testing.T) {
	data := makeZip(t, []entry{
		{name: "folder/", isDir: true},
		{name: "readme.txt", content: "plain text"}, // just noise, not encrypted
		{name: "secret.txt", content: "the goods", password: "ab", enc: zip.AES256Encryption},
	})
	// 'a' is the first length-1 try, old code spat it out instantly
	got, ok := newCracker(t, data, "ab", 1, 2).Crack()
	if !ok {
		t.Fatal("password not found")
	}
	if got != "ab" {
		t.Errorf("Crack = %q, want ab (false positive on first entry?)", got)
	}
}

func TestCrack_Regression_UnencryptedFirst_ZipCrypto(t *testing.T) {
	data := makeZip(t, []entry{
		{name: "readme.txt", content: "plain"},
		{name: "secret.txt", content: "the goods", password: "bc", enc: zip.StandardEncryption},
	})
	if got, ok := newCracker(t, data, "abc", 1, 2).Crack(); !ok || got != "bc" {
		t.Errorf("Crack = (%q, %v), want (bc, true)", got, ok)
	}
}
