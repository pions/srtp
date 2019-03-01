package srtp

import (
	"bytes"
	"fmt"
	"io"
	"net"

	"github.com/pions/rtcp"
	"github.com/pions/webrtc/pkg/logging"
)

// SessionSRTCP implements io.ReadWriteCloser and provides a bi-directional SRTCP session
// SRTCP itself does not have a design like this, but it is common in most applications
// for local/remote to each have their own keying material. This provides those patterns
// instead of making everyone re-implement
type SessionSRTCP struct {
	session
	writeStream *WriteStreamSRTCP
}

var srtcpLog = logging.NewScopedLogger("srtcp")

// NewSessionSRTCP creates a SRTCP session using conn as the underlying transport.
func NewSessionSRTCP(conn net.Conn, config *Config) (*SessionSRTCP, error) {
	s := &SessionSRTCP{
		session: session{
			nextConn:    conn,
			readStreams: map[uint32]readStream{},
			newStream:   make(chan readStream),
			started:     make(chan interface{}),
			closed:      make(chan interface{}),
		},
	}
	s.writeStream = &WriteStreamSRTCP{s}

	err := s.session.start(
		config.Keys.LocalMasterKey, config.Keys.LocalMasterSalt,
		config.Keys.RemoteMasterKey, config.Keys.RemoteMasterSalt,
		config.Profile,
		s,
	)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// OpenWriteStream returns the global write stream for the Session
func (s *SessionSRTCP) OpenWriteStream() (*WriteStreamSRTCP, error) {
	return s.writeStream, nil
}

// OpenReadStream opens a read stream for the given SSRC, it can be used
// if you want a certain SSRC, but don't want to wait for AcceptStream
func (s *SessionSRTCP) OpenReadStream(SSRC uint32) (*ReadStreamSRTCP, error) {
	r, _ := s.session.getOrCreateReadStream(SSRC, s, &ReadStreamSRTCP{})

	if readStream, ok := r.(*ReadStreamSRTCP); ok {
		return readStream, nil
	}
	return nil, fmt.Errorf("failed to open ReadStreamSRCTP, type assertion failed")
}

// AcceptStream returns a stream to handle RTCP for a single SSRC
func (s *SessionSRTCP) AcceptStream() (*ReadStreamSRTCP, uint32, error) {
	stream, ok := <-s.newStream
	if !ok {
		return nil, 0, fmt.Errorf("SessionSRTCP has been closed")
	}

	readStream, ok := stream.(*ReadStreamSRTCP)
	if !ok {
		return nil, 0, fmt.Errorf("newStream was found, but failed type assertion")
	}

	return readStream, stream.GetSSRC(), nil
}

// Close ends the session
func (s *SessionSRTCP) Close() error {
	return s.session.close()
}

// Private

func (s *SessionSRTCP) write(buf []byte) (int, error) {
	if _, ok := <-s.session.started; ok {
		return 0, fmt.Errorf("started channel used incorrectly, should only be closed")
	}

	s.session.localContextMutex.Lock()
	defer s.session.localContextMutex.Unlock()

	encrypted, err := s.localContext.EncryptRTCP(nil, buf, nil)
	if err != nil {
		return 0, err
	}
	return s.session.nextConn.Write(encrypted)
}

func (s *SessionSRTCP) decrypt(buf []byte) error {
	decrypted, err := s.remoteContext.DecryptRTCP(nil, buf, nil)
	if err != nil {
		return err
	}

	compoundPacket := rtcp.NewReader(bytes.NewReader(decrypted))
	for {
		_, rawrtcp, err := compoundPacket.ReadPacket()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		var report rtcp.Packet
		report, _, err = rtcp.Unmarshal(rawrtcp)
		if err != nil {
			return err
		}

		srtcpLog.Tracef("Receive rtcp: %+v, header: %+v", report, report.Header())

		for _, ssrc := range report.DestinationSSRC() {
			r, isNew := s.session.getOrCreateReadStream(ssrc, s, &ReadStreamSRTCP{})
			if r == nil {
				return nil // Session has been closed
			} else if isNew {
				s.session.newStream <- r // Notify AcceptStream
			}

			readStream, ok := r.(*ReadStreamSRTCP)
			if !ok {
				return fmt.Errorf("failed to get/create ReadStreamSRTP")
			}

			// Ensure that readStream.Close() isn't called while in flight
			readStream.mu.Lock()
			defer readStream.mu.Unlock()

			readBuf := <-readStream.readCh
			if len(readBuf) < len(decrypted) {
				return fmt.Errorf("input buffer was not long enough to contain decrypted RTCP")
			}

			copy(readBuf, decrypted)
			h := report.Header()

			readStream.readRetCh <- readResultSRTCP{
				len:    len(decrypted),
				header: &h,
			}
		}
	}
}
