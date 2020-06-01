package srtp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
	"testing"
)

func xorBytesCTRReference(block cipher.Block, iv []byte, dst, src []byte) {
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(dst, src)
}

func TestXorBytesCTR(t *testing.T) {
	for keysize := 16; keysize < 64; keysize *= 2 {
		key := make([]byte, keysize)
		_, err := rand.Read(key)
		if err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatalf("NewCipher: %v", err)
		}
		iv := make([]byte, block.BlockSize())
		for i := 0; i < 1500; i++ {
			src := make([]byte, i)
			dst := make([]byte, i)
			reference := make([]byte, i)
			_, err = rand.Read(iv)
			if err != nil {
				t.Fatalf("rand.Read: %v", err)
			}
			_, err = rand.Read(src)
			if err != nil {
				t.Fatalf("rand.Read: %v", err)
			}
			xorBytesCTR(block, iv, dst, src)
			xorBytesCTRReference(block, iv, reference, src)
			if !bytes.Equal(dst, reference) {
				t.Errorf("Mismatch for keysize %v, data size %v",
					keysize, i)
			}

			// test overlap
			xorBytesCTR(block, iv, dst, dst)
			xorBytesCTRReference(block, iv, reference, reference)
			if !bytes.Equal(dst, reference) {
				t.Errorf("Mismatch (overlapping) for keysize %v, data size %v",
					keysize, i)
			}
		}
	}
}

func TestXorBytesCTRInvalidIvLength(t *testing.T) {
	key := make([]byte, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	src := make([]byte, 1024)
	dst := make([]byte, 1024)

	test := func(iv []byte) {
		defer func() {
			p := recover()
			if p == nil {
				t.Errorf("xorBytesCTR didn't panic with iv of length %v", len(iv))
			}
		}()
		xorBytesCTR(block, iv, dst, src)
	}

	test(make([]byte, block.BlockSize() - 1))
	test(make([]byte, block.BlockSize() + 1))
}

func TestXorBytesBufferSize(t *testing.T) {
	a := []byte{3}
	b := []byte{5, 6}
	dst := make([]byte, 3)

	xorBytes(dst, a, b)
	if !bytes.Equal(dst, []byte{6, 0, 0}) {
		t.Errorf("Expected [6 0 0], got %v", dst)
	}

	xorBytes(dst, b, a)
	if !bytes.Equal(dst, []byte{6, 0, 0}) {
		t.Errorf("Expected [6 6 0], got %v", dst)
	}

	a = []byte{1, 1, 1, 1}
	b = []byte{2, 2, 2, 2}
	dst = make([]byte, 3)

	xorBytes(dst, a, b)
	if !bytes.Equal(dst, []byte{3, 3, 3}) {
		t.Errorf("Expected [3 3 3], got %v", dst)
	}
}

func benchmarkXorBytesCTR(b *testing.B, size int) {
	key := make([]byte, 16)
	rand.Read(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		b.Fatalf("NewCipher: %v", err)
	}
	iv := make([]byte, 16)
	src := make([]byte, 1024)
	dst := make([]byte, 1024)

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rand.Read(iv)
		rand.Read(src)
		xorBytesCTR(block, iv, dst, src)
	}
}

func BenchmarkXorBytesCTR14(b *testing.B) {
	benchmarkXorBytesCTR(b, 14)
}

func BenchmarkXorBytesCTR140(b *testing.B) {
	benchmarkXorBytesCTR(b, 140)
}

func BenchmarkXorBytesCTR1400(b *testing.B) {
	benchmarkXorBytesCTR(b, 1400)
}

func benchmarkXorBytesCTRReference(b *testing.B, size int) {
	key := make([]byte, 16)
	rand.Read(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		b.Fatalf("NewCipher: %v", err)
	}
	iv := make([]byte, 16)
	src := make([]byte, 1024)
	dst := make([]byte, 1024)

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rand.Read(iv)
		rand.Read(src)
		xorBytesCTRReference(block, iv, dst, src)
	}
}

func BenchmarkXorBytesCTR14Reference(b *testing.B) {
	benchmarkXorBytesCTRReference(b, 14)
}

func BenchmarkXorBytesCTR140Reference(b *testing.B) {
	benchmarkXorBytesCTRReference(b, 140)
}

func BenchmarkXorBytesCTR1400Reference(b *testing.B) {
	benchmarkXorBytesCTRReference(b, 1400)
}
