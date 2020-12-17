package srtp

import (
	"bytes"
	"errors"
	"testing"

	"github.com/pion/rtp"
	"github.com/stretchr/testify/assert"
)

const (
	cipherContextAlgo = ProtectionProfileAes128CmHmacSha1_80
	defaultSsrc       = 0
)

type rtpTestCase struct {
	sequenceNumber uint16
	encrypted      []byte
}

func TestKeyLen(t *testing.T) {
	keyLen, err := cipherContextAlgo.keyLen()
	assert.NoError(t, err)

	saltLen, err := cipherContextAlgo.saltLen()
	assert.NoError(t, err)

	if _, err := CreateContext([]byte{}, make([]byte, saltLen), cipherContextAlgo); err == nil {
		t.Errorf("CreateContext accepted a 0 length key")
	}

	if _, err := CreateContext(make([]byte, keyLen), []byte{}, cipherContextAlgo); err == nil {
		t.Errorf("CreateContext accepted a 0 length salt")
	}

	if _, err := CreateContext(make([]byte, keyLen), make([]byte, saltLen), cipherContextAlgo); err != nil {
		t.Errorf("CreateContext failed with a valid length key and salt: %v", err)
	}
}

func TestValidPacketCounter(t *testing.T) {
	masterKey := []byte{0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28, 0x89}
	masterSalt := []byte{0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c}

	srtpSessionSalt, err := aesCmKeyDerivation(labelSRTPSalt, masterKey, masterSalt, 0, len(masterSalt))
	assert.NoError(t, err)

	s := &srtpSSRCState{ssrc: 4160032510}
	expectedCounter := []byte{0xcf, 0x90, 0x1e, 0xa5, 0xda, 0xd3, 0x2c, 0x15, 0x00, 0xa2, 0x24, 0xae, 0xae, 0xaf, 0x00, 0x00}
	counter := generateCounter(32846, s.rolloverCounter, s.ssrc, srtpSessionSalt)
	if !bytes.Equal(counter, expectedCounter) {
		t.Errorf("Session Key % 02x does not match expected % 02x", counter, expectedCounter)
	}
}

func TestRolloverCount(t *testing.T) {
	s := &srtpSSRCState{ssrc: defaultSsrc}

	// Set initial seqnum
	roc, update := s.nextRolloverCount(65530)
	if roc != 0 {
		t.Errorf("Initial rolloverCounter must be 0")
	}
	update()

	// Invalid packets never update ROC
	_, _ = s.nextRolloverCount(0)
	_, _ = s.nextRolloverCount(0x4000)
	_, _ = s.nextRolloverCount(0x8000)
	_, _ = s.nextRolloverCount(0xFFFF)
	_, _ = s.nextRolloverCount(0)

	// We rolled over to 0
	roc, update = s.nextRolloverCount(0)
	if roc != 1 {
		t.Errorf("rolloverCounter was not updated after it crossed 0")
	}
	update()

	roc, update = s.nextRolloverCount(65530)
	if roc != 0 {
		t.Errorf("rolloverCounter was not updated when it rolled back, failed to handle out of order")
	}
	update()

	roc, update = s.nextRolloverCount(5)
	if roc != 1 {
		t.Errorf("rolloverCounter was not updated when it rolled over initial, to handle out of order")
	}
	update()

	_, update = s.nextRolloverCount(6)
	update()
	_, update = s.nextRolloverCount(7)
	update()
	roc, update = s.nextRolloverCount(8)
	if roc != 1 {
		t.Errorf("rolloverCounter was improperly updated for non-significant packets")
	}
	update()

	// valid packets never update ROC
	roc, update = s.nextRolloverCount(0x4000)
	if roc != 1 {
		t.Errorf("rolloverCounter was improperly updated for non-significant packets")
	}
	update()
	roc, update = s.nextRolloverCount(0x8000)
	if roc != 1 {
		t.Errorf("rolloverCounter was improperly updated for non-significant packets")
	}
	update()
	roc, update = s.nextRolloverCount(0xFFFF)
	if roc != 1 {
		t.Errorf("rolloverCounter was improperly updated for non-significant packets")
	}
	update()
	roc, _ = s.nextRolloverCount(0)
	if roc != 2 {
		t.Errorf("rolloverCounter must be incremented after wrapping, got %d", roc)
	}
}

func buildTestContext(opts ...ContextOption) (*Context, error) {
	masterKey := []byte{0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28, 0x89}
	masterSalt := []byte{0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c}

	return CreateContext(masterKey, masterSalt, cipherContextAlgo, opts...)
}

func TestRTPInvalidAuth(t *testing.T) {
	masterKey := []byte{0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28, 0x89}
	invalidSalt := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	encryptContext, err := buildTestContext()
	if err != nil {
		t.Fatal(err)
	}

	invalidContext, err := CreateContext(masterKey, invalidSalt, cipherContextAlgo)
	if err != nil {
		t.Errorf("CreateContext failed: %v", err)
	}

	for _, testCase := range rtpTestCases() {
		pkt := &rtp.Packet{Payload: rtpTestCaseDecrypted(), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		pktRaw, err := pkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		out, err := encryptContext.EncryptRTP(nil, pktRaw, nil)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := invalidContext.DecryptRTP(nil, out, nil); err == nil {
			t.Errorf("Managed to decrypt with incorrect salt for packet with SeqNum: %d", testCase.sequenceNumber)
		}
	}
}

func rtpTestCaseDecrypted() []byte { return []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05} }

func rtpTestCases() []rtpTestCase {
	return []rtpTestCase{
		{
			sequenceNumber: 5000,
			encrypted:      []byte{0x6d, 0xd3, 0x7e, 0xd5, 0x99, 0xb7, 0x2d, 0x28, 0xb1, 0xf3, 0xa1, 0xf0, 0xc, 0xfb, 0xfd, 0x8},
		},
		{
			sequenceNumber: 5001,
			encrypted:      []byte{0xda, 0x47, 0xb, 0x2a, 0x74, 0x53, 0x65, 0xbd, 0x2f, 0xeb, 0xdc, 0x4b, 0x6d, 0x23, 0xf3, 0xde},
		},
		{
			sequenceNumber: 5002,
			encrypted:      []byte{0x6e, 0xa7, 0x69, 0x8d, 0x24, 0x6d, 0xdc, 0xbf, 0xec, 0x2, 0x1c, 0xd1, 0x60, 0x76, 0xc1, 0xe},
		},
		{
			sequenceNumber: 5003,
			encrypted:      []byte{0x24, 0x7e, 0x96, 0xc8, 0x7d, 0x33, 0xa2, 0x92, 0x8d, 0x13, 0x8d, 0xe0, 0x76, 0x9f, 0x8, 0xdc},
		},
		{
			sequenceNumber: 5004,
			encrypted:      []byte{0x75, 0x43, 0x28, 0xe4, 0x3a, 0x77, 0x59, 0x9b, 0x2e, 0xdf, 0x7b, 0x12, 0x68, 0xb, 0x57, 0x49},
		},
		{
			sequenceNumber: 65535, // upper boundary
			encrypted:      []byte{0xaf, 0xf7, 0xc2, 0x70, 0x37, 0x20, 0x83, 0x9c, 0x2c, 0x63, 0x85, 0x15, 0xe, 0x44, 0xca, 0x36},
		},
	}
}

func TestRTPLifecyleNewAlloc(t *testing.T) {
	assert := assert.New(t)

	authTagLen, err := ProtectionProfileAes128CmHmacSha1_80.authTagLen()
	assert.NoError(err)

	for _, testCase := range rtpTestCases() {
		encryptContext, err := buildTestContext()
		if err != nil {
			t.Fatal(err)
		}

		decryptContext, err := buildTestContext()
		if err != nil {
			t.Fatal(err)
		}

		decryptedPkt := &rtp.Packet{Payload: rtpTestCaseDecrypted(), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		decryptedRaw, err := decryptedPkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		encryptedPkt := &rtp.Packet{Payload: testCase.encrypted, Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		encryptedRaw, err := encryptedPkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		actualEncrypted, err := encryptContext.EncryptRTP(nil, decryptedRaw, nil)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equalf(actualEncrypted, encryptedRaw, "RTP packet with SeqNum invalid encryption: %d", testCase.sequenceNumber)

		actualDecrypted, err := decryptContext.DecryptRTP(nil, encryptedRaw, nil)
		if err != nil {
			t.Fatal(err)
		} else if bytes.Equal(encryptedRaw[:len(encryptedRaw)-authTagLen], actualDecrypted) {
			t.Fatal("DecryptRTP improperly encrypted in place")
		}

		assert.Equalf(actualDecrypted, decryptedRaw, "RTP packet with SeqNum invalid decryption: %d", testCase.sequenceNumber)
	}
}

func TestRTPLifecyleInPlace(t *testing.T) {
	assert := assert.New(t)

	for _, testCase := range rtpTestCases() {
		encryptContext, err := buildTestContext()
		if err != nil {
			t.Fatal(err)
		}

		decryptContext, err := buildTestContext()
		if err != nil {
			t.Fatal(err)
		}

		decryptHeader := &rtp.Header{}
		decryptedPkt := &rtp.Packet{Payload: rtpTestCaseDecrypted(), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		decryptedRaw, err := decryptedPkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		encryptHeader := &rtp.Header{}
		encryptedPkt := &rtp.Packet{Payload: testCase.encrypted, Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		encryptedRaw, err := encryptedPkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		// Copy packet, asserts that everything was done in place
		encryptInput := make([]byte, len(decryptedRaw), len(decryptedRaw)+10)
		copy(encryptInput, decryptedRaw)

		actualEncrypted, err := encryptContext.EncryptRTP(encryptInput, encryptInput, encryptHeader)
		switch {
		case err != nil:
			t.Fatal(err)
		case &encryptInput[0] != &actualEncrypted[0]:
			t.Fatal("EncryptRTP failed to encrypt in place")
		case encryptHeader.SequenceNumber != testCase.sequenceNumber:
			t.Fatal("EncryptRTP failed to populate input rtp.Header")
		}
		assert.Equalf(actualEncrypted, encryptedRaw, "RTP packet with SeqNum invalid encryption: %d", testCase.sequenceNumber)

		// Copy packet, asserts that everything was done in place
		decryptInput := make([]byte, len(encryptedRaw))
		copy(decryptInput, encryptedRaw)

		actualDecrypted, err := decryptContext.DecryptRTP(decryptInput, decryptInput, decryptHeader)
		switch {
		case err != nil:
			t.Fatal(err)
		case &decryptInput[0] != &actualDecrypted[0]:
			t.Fatal("DecryptRTP failed to decrypt in place")
		case decryptHeader.SequenceNumber != testCase.sequenceNumber:
			t.Fatal("DecryptRTP failed to populate input rtp.Header")
		}
		assert.Equalf(actualDecrypted, decryptedRaw, "RTP packet with SeqNum invalid decryption: %d", testCase.sequenceNumber)
	}
}

func TestRTPReplayProtection(t *testing.T) {
	assert := assert.New(t)

	for _, testCase := range rtpTestCases() {
		encryptContext, err := buildTestContext()
		if err != nil {
			t.Fatal(err)
		}

		decryptContext, err := buildTestContext(SRTPReplayProtection(64))
		if err != nil {
			t.Fatal(err)
		}

		decryptHeader := &rtp.Header{}
		decryptedPkt := &rtp.Packet{Payload: rtpTestCaseDecrypted(), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		decryptedRaw, err := decryptedPkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		encryptHeader := &rtp.Header{}
		encryptedPkt := &rtp.Packet{Payload: testCase.encrypted, Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		encryptedRaw, err := encryptedPkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		// Copy packet, asserts that everything was done in place
		encryptInput := make([]byte, len(decryptedRaw), len(decryptedRaw)+10)
		copy(encryptInput, decryptedRaw)

		actualEncrypted, err := encryptContext.EncryptRTP(encryptInput, encryptInput, encryptHeader)
		switch {
		case err != nil:
			t.Fatal(err)
		case &encryptInput[0] != &actualEncrypted[0]:
			t.Fatal("EncryptRTP failed to encrypt in place")
		case encryptHeader.SequenceNumber != testCase.sequenceNumber:
			t.Fatal("EncryptRTP failed to populate input rtp.Header")
		}
		assert.Equalf(actualEncrypted, encryptedRaw, "RTP packet with SeqNum invalid encryption: %d", testCase.sequenceNumber)

		// Copy packet, asserts that everything was done in place
		decryptInput := make([]byte, len(encryptedRaw))
		copy(decryptInput, encryptedRaw)

		actualDecrypted, err := decryptContext.DecryptRTP(decryptInput, decryptInput, decryptHeader)
		switch {
		case err != nil:
			t.Fatal(err)
		case &decryptInput[0] != &actualDecrypted[0]:
			t.Fatal("DecryptRTP failed to decrypt in place")
		case decryptHeader.SequenceNumber != testCase.sequenceNumber:
			t.Fatal("DecryptRTP failed to populate input rtp.Header")
		}
		assert.Equalf(actualDecrypted, decryptedRaw, "RTP packet with SeqNum invalid decryption: %d", testCase.sequenceNumber)

		_, errReplay := decryptContext.DecryptRTP(decryptInput, decryptInput, decryptHeader)
		if !errors.Is(errReplay, errDuplicated) {
			t.Errorf("Replayed packet must be errored with %v, got %v", errDuplicated, errReplay)
		}
	}
}

func benchmarkEncryptRTP(b *testing.B, size int) {
	encryptContext, err := buildTestContext()
	if err != nil {
		b.Fatal(err)
	}

	pkt := &rtp.Packet{Payload: make([]byte, size)}
	pktRaw, err := pkt.Marshal()
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(pktRaw)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err = encryptContext.EncryptRTP(nil, pktRaw, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptRTP14(b *testing.B) {
	benchmarkEncryptRTP(b, 14)
}

func BenchmarkEncryptRTP140(b *testing.B) {
	benchmarkEncryptRTP(b, 140)
}

func BenchmarkEncryptRTP1400(b *testing.B) {
	benchmarkEncryptRTP(b, 1400)
}

func benchmarkEncryptRTPInPlace(b *testing.B, size int) {
	encryptContext, err := buildTestContext()
	if err != nil {
		b.Fatal(err)
	}

	pkt := &rtp.Packet{Payload: make([]byte, size)}
	pktRaw, err := pkt.Marshal()
	if err != nil {
		b.Fatal(err)
	}

	buf := make([]byte, 0, len(pktRaw)+10)

	b.SetBytes(int64(len(pktRaw)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf, err = encryptContext.EncryptRTP(buf[:0], pktRaw, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptRTPInPlace14(b *testing.B) {
	benchmarkEncryptRTPInPlace(b, 14)
}

func BenchmarkEncryptRTPInPlace140(b *testing.B) {
	benchmarkEncryptRTPInPlace(b, 140)
}

func BenchmarkEncryptRTPInPlace1400(b *testing.B) {
	benchmarkEncryptRTPInPlace(b, 1400)
}

func BenchmarkDecryptRTP(b *testing.B) {
	sequenceNumber := uint16(5000)
	encrypted := []byte{0x6d, 0xd3, 0x7e, 0xd5, 0x99, 0xb7, 0x2d, 0x28, 0xb1, 0xf3, 0xa1, 0xf0, 0xc, 0xfb, 0xfd, 0x8}

	encryptedPkt := &rtp.Packet{
		Payload: encrypted,
		Header: rtp.Header{
			SequenceNumber: sequenceNumber,
		},
	}

	encryptedRaw, err := encryptedPkt.Marshal()
	if err != nil {
		b.Fatal(err)
	}

	context, err := buildTestContext()
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(encryptedRaw)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := context.DecryptRTP(nil, encryptedRaw, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
