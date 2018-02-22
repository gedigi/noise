package noise

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Conn represents a secured connection.
// It implements the net.Conn interface.
type Conn struct {
	conn     net.Conn
	isClient bool

	// handshake
	config            *Config // configuration passed to constructor
	hs                *HandshakeState
	handshakeComplete bool
	handshakeMutex    sync.Mutex

	// Authentication
	isRemoteAuthenticated bool

	// input/output
	in, out         *CipherState
	inLock, outLock sync.Mutex
	inputBuffer     []byte
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the connection.
// A zero value for t means Read and Write will not time out.
// After a Write has timed out, the Noise state is corrupt and all future writes will return the same error.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying connection.
// A zero value for t means Read will not time out.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection.
// A zero value for t means Write will not time out.
// After a Write has timed out, the Noise state is corrupt and all future writes will return the same error.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// Write writes data to the connection.
func (c *Conn) Write(b []byte) (int, error) {

	//
	if hp := c.config.Pattern; !c.isClient && len(hp.Messages) < 2 {
		return 0, errors.New("A server should not write on one-way patterns")
	}

	// Make sure to go through the handshake first
	if err := c.Handshake(); err != nil {
		return 0, err
	}

	// Lock the write socket
	c.outLock.Lock()
	defer c.outLock.Unlock()

	// process the data in a loop
	var n int
	data := b
	for len(data) > 0 {

		// fragment the data
		m := len(data)
		if m > MaxMsgLen {
			m = MaxMsgLen
		}

		// Encrypt
		ciphertext := c.out.Encrypt(nil, nil, data[:m])

		// header (length)
		length := []byte{byte(len(ciphertext) >> 8), byte(len(ciphertext) % 256)}

		// Send data
		_, err := c.conn.Write(append(length, ciphertext...))
		// _, err := c.conn.Write(ciphertext)
		if err != nil {
			return n, err
		}

		// prepare next loop iteration
		n += m
		data = data[m:]
	}

	return n, nil
}

// Read can be made to time out and return a net.Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetReadDeadline.
func (c *Conn) Read(b []byte) (n int, err error) {
	// Make sure to go through the handshake first
	if err = c.Handshake(); err != nil {
		return
	}

	// Put this after Handshake, in case people were calling
	// Read(nil) for the side effect of the Handshake.
	if len(b) == 0 {
		return
	}

	// If this is a one-way pattern, do some checks
	if hp := c.config.Pattern; !c.isClient && len(hp.Messages) < 2 {
		return 0, errors.New("A client should not read on one-way patterns")
	}

	// Lock the read socket
	c.inLock.Lock()
	defer c.inLock.Unlock()

	// read whatever there is to read in the buffer
	readSoFar := 0
	if len(c.inputBuffer) > 0 {
		copy(b, c.inputBuffer)
		if len(c.inputBuffer) >= len(b) {
			c.inputBuffer = c.inputBuffer[len(b):]
			return len(b), nil
		}
		readSoFar += len(c.inputBuffer)
		c.inputBuffer = c.inputBuffer[:0]
	}

	// read header from socket
	bufHeader, err := readFromUntil(c.conn, 2)
	if err != nil {
		return 0, err
	}
	length := (int(bufHeader[0]) << 8) | int(bufHeader[1])
	if length > MaxMsgLen {
		return 2, errors.New("Noise: Noise message received exceeds NoiseMessageLength")
	}

	// read noise message from socket
	noiseMessage, err := readFromUntil(c.conn, length)
	if err != nil {
		return 0, err
	}

	// decrypt
	plaintext, err := c.in.Decrypt(nil, nil, noiseMessage)
	if err != nil {
		return 0, err
	}

	// append to the input buffer
	c.inputBuffer = append(c.inputBuffer, plaintext...)

	// read whatever we can read
	rest := len(b) - readSoFar
	copy(b[readSoFar:], c.inputBuffer)
	if len(c.inputBuffer) >= rest {
		c.inputBuffer = c.inputBuffer[rest:]
		return len(b), nil
	}

	// we haven't filled the buffer
	readSoFar += len(c.inputBuffer)
	c.inputBuffer = c.inputBuffer[:0]
	return readSoFar, nil

}

// Close closes the connection.
func (c *Conn) Close() error {
	return c.conn.Close()
}

// Noise-related functions

// Handshake runs the client or server handshake protocol if
// it has not yet been run.
// Most uses of this package need not call Handshake explicitly:
// the first Read or Write will call it automatically.
func (c *Conn) Handshake() (err error) {

	// Locking the handshakeMutex
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	// did we already go through the handshake?
	if c.handshakeComplete {
		return nil
	}

	var remoteKeyPair *DHKey
	if c.config.PeerStatic != nil {
		if len(c.config.PeerStatic) != 32 {
			return errors.New("noise: the provided remote key is not 32-byte")
		}
		remoteKeyPair = &DHKey{}
		copy(remoteKeyPair.Public[:], c.config.PeerStatic)
	}
	c.hs, err = NewHandshakeState(*c.config)
	if err != nil {
		return err
	}

	// start handshake
	var c1, c2 *CipherState
	var state bool
	var msg []byte
	state = c.isClient
	for _ = range c.config.Pattern.Messages {
		if state {
			msg, c1, c2, err = c.hs.WriteMessage(nil, nil)
			if err != nil {
				return err
			}
			// header (length)
			length := []byte{byte(len(msg) >> 8), byte(len(msg) % 256)}
			// write
			_, err = c.conn.Write(append(length, msg...))
			if err != nil {
				return err
			}
		} else {
			bufHeader, err := readFromUntil(c.conn, 2)
			if err != nil {
				return err
			}
			length := (int(bufHeader[0]) << 8) | int(bufHeader[1])
			if length > MaxMsgLen {
				return errors.New("Noise: Noise message received exceeds NoiseMessageLength")
			}

			msg, err = readFromUntil(c.conn, length)

			if err != nil {
				return err
			}
			_, c1, c2, err = c.hs.ReadMessage(nil, msg)
			if err != nil {
				return err
			}
		}
		state = !state
	}

	if c.isClient {
		c.out, c.in = c1, c2
	} else {
		c.out, c.in = c2, c1
	}
	c.handshakeComplete = true
	return nil
}

// IsRemoteAuthenticated can be used to check if the remote peer has been
// properly authenticated. It serves no real purpose for the moment as the
// handshake will not go through if a peer is not properly authenticated in
// patterns where the peer needs to be authenticated.
func (c *Conn) IsRemoteAuthenticated() bool {
	return c.isRemoteAuthenticated
}

// RemoteKey returns the static key of the remote peer.
// It is useful in case the static key is only transmitted during the handshake.
func (c *Conn) RemoteKey() ([]byte, error) {
	if !c.handshakeComplete {
		return nil, errors.New("handshake not completed")
	}
	return c.hs.rs, nil
}

// These Utility functions implement the net.Conn interface. Most of this code
// was either taken directly or inspired from Go's crypto/tls package.

// Server returns a new Noise server side connection
// using net.Conn as the underlying transport.
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func Server(conn net.Conn, config *Config) Conn {
	return Conn{conn: conn, config: config, isClient: false}
}

// Client returns a new Noise client side connection
// using conn as the underlying transport.
// The config cannot be nil: users must set either ServerName or
// InsecureSkipVerify in the config.
func Client(conn net.Conn, config *Config) *Conn {
	return &Conn{conn: conn, config: config, isClient: true}
}

// A listener implements a network listener (net.Listener) for Noise connections.
type listener struct {
	net.Listener
	config *Config
}

// Accept waits for and returns the next incoming Noise connection.
// The returned connection is of type *Conn.
func (l *listener) Accept() (Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return Conn{}, err
	}
	return Server(c, l.config), nil
}
func (l *listener) Close() error {
	return l.Listener.Close()
}
func (l *listener) Addr() net.Addr {
	return l.Listener.Addr()
}

// Listen creates a Noise listener accepting connections on the
// given network address using net.Listen.
// The configuration config must be non-nil.
func Listen(network, laddr string, config *Config) (net.Listener, error) {
	// check Config
	if config == nil {
		return nil, errors.New("Noise: no Config set")
	}
	// if err := checkRequirements(config); err != nil {
	// 	panic(err)
	// }

	// make net.Conn listen
	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}

	// create new noise.listener
	noiseListener := new(listener)
	noiseListener.Listener = l
	noiseListener.config = config
	return noiseListener, nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "noise: DialWithDialer timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// DialWithDialer connects to the given network address using dialer.Dial and
// then initiates a Noise handshake, returning the resulting Noise connection. Any
// timeout or deadline given in the dialer apply to connection and Noise
// handshake as a whole.
func DialWithDialer(dialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	// We want the Timeout and Deadline values from dialer to cover the
	// whole process: TCP connection and Noise handshake. This means that we
	// also need to start our own timers now.
	timeout := dialer.Timeout

	if !dialer.Deadline.IsZero() {
		deadlineTimeout := time.Until(dialer.Deadline)
		if timeout == 0 || deadlineTimeout < timeout {
			timeout = deadlineTimeout
		}
	}

	// check Config
	if config == nil {
		return nil, errors.New("empty noise.Config")
	}

	// Dial the net.Conn first
	var errChannel chan error

	if timeout != 0 {
		errChannel = make(chan error, 2)
		time.AfterFunc(timeout, func() {
			errChannel <- timeoutError{}
		})
	}

	rawConn, err := dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	// Create the noise.Conn
	conn := Client(rawConn, config)

	// Do the handshake
	if timeout == 0 {
		err = conn.Handshake()
	} else {
		go func() {
			errChannel <- conn.Handshake()
		}()

		err = <-errChannel
	}

	if err != nil {
		rawConn.Close()
		return nil, err
	}

	return conn, nil
}

// Dial connects to the given network address using net.Dial
// and then initiates a Noise handshake, returning the resulting
// Noise connection.
func Dial(network, addr string, config *Config) (*Conn, error) {
	return DialWithDialer(new(net.Dialer), network, addr, config)
}

// input/output functions

func readFromUntil(r io.Reader, n int) ([]byte, error) {
	result := make([]byte, n)
	offset := 0
	for {
		m, err := r.Read(result[offset:])
		if err != nil {
			return result, err
		}
		offset += m
		if offset == n {
			break
		}
	}
	return result, nil
}
