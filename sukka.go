package sukka

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
)

const (
	defaultListenAddr = ":1080"

	socksVersion byte = 0x05
	reservedByte byte = 0x00

	methodNoAuthRequired   byte = 0x00
	methodUsernamePassword byte = 0x02
	methodNoAcceptable     byte = 0xFF

	commandConnect byte = 0x01

	addressTypeIPv4   byte = 0x01
	addressTypeDomain byte = 0x03
	addressTypeIPv6   byte = 0x04

	replySucceeded           byte = 0x00
	replyGeneralFailure      byte = 0x01
	replyCommandNotSupported byte = 0x07
	replyAddressNotSupported byte = 0x08
)

var (
	ErrUnsupportedVersion  = errors.New("unsupported SOCKS version")
	ErrNoAcceptableMethod  = errors.New("no acceptable authentication method")
	ErrUnsupportedCommand  = errors.New("command not supported")
	ErrUnsupportedAddrType = errors.New("address type not supported")
	ErrInvalidReservedByte = errors.New("request reserved byte must be 0x00")
	ErrNilListener         = errors.New("listener must not be nil")
)

type Server struct {
	Addr   string
	Logger *log.Logger
	Dial   func(network, address string) (net.Conn, error)
}

func (s *Server) handleConn(c net.Conn) error {
	defer c.Close()

	if err := negotiateMethod(c); err != nil {
		return err
	}

	command, destination, err := readRequest(c)
	if err != nil {
		if errors.Is(err, ErrUnsupportedAddrType) {
			if writeErr := writeReply(c, replyAddressNotSupported, nil); writeErr != nil {
				return writeErr
			}
		} else if errors.Is(err, ErrInvalidReservedByte) {
			if writeErr := writeReply(c, replyGeneralFailure, nil); writeErr != nil {
				return writeErr
			}
		}

		return err
	}

	if command != commandConnect {
		if err := writeReply(c, replyCommandNotSupported, nil); err != nil {
			return err
		}

		return fmt.Errorf("%w: 0x%02x", ErrUnsupportedCommand, command)
	}

	target, err := s.dialConn("tcp", destination)
	if err != nil {
		if writeErr := writeReply(c, replyGeneralFailure, nil); writeErr != nil {
			return writeErr
		}

		return fmt.Errorf("dial %s: %w", destination, err)
	}
	defer target.Close()

	if err := writeReply(c, replySucceeded, target.LocalAddr()); err != nil {
		return err
	}

	errCh := make(chan error, 2)

	go func() {
		_, copyErr := io.Copy(target, c)
		_ = closeWrite(target)
		errCh <- copyErr
	}()

	go func() {
		_, copyErr := io.Copy(c, target)
		_ = closeWrite(c)
		errCh <- copyErr
	}()

	var relayErr error
	for i := 0; i < 2; i++ {
		copyErr := <-errCh
		if relayErr == nil && copyErr != nil && !errors.Is(copyErr, io.EOF) && !errors.Is(copyErr, net.ErrClosed) && !errors.Is(copyErr, io.ErrClosedPipe) {
			relayErr = copyErr
		}
	}

	return relayErr
}

func RunServer() error {
	return new(Server).ListenAndServe()
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.listenAddr())
	if err != nil {
		return err
	}

	return s.Serve(ln)
}

func (s *Server) Serve(ln net.Listener) error {
	if ln == nil {
		return ErrNilListener
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				s.logger().Println(err)
				continue
			}

			return err
		}

		go func(conn net.Conn) {
			if err := s.handleConn(conn); err != nil {
				s.logger().Println(err)
			}
		}(conn)
	}
}

func (s *Server) dialConn(network, address string) (net.Conn, error) {
	if s != nil && s.Dial != nil {
		return s.Dial(network, address)
	}

	return net.Dial(network, address)
}

func (s *Server) listenAddr() string {
	if s != nil && s.Addr != "" {
		return s.Addr
	}

	return defaultListenAddr
}

func (s *Server) logger() *log.Logger {
	if s != nil && s.Logger != nil {
		return s.Logger
	}

	return log.Default()
}

func negotiateMethod(c net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(c, header); err != nil {
		return err
	}

	if header[0] != socksVersion {
		return fmt.Errorf("%w: got 0x%02x", ErrUnsupportedVersion, header[0])
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}

	selectedMethod := methodNoAcceptable

	for _, method := range methods {
		if method == methodNoAuthRequired {
			selectedMethod = methodNoAuthRequired
			break
		}
	}

	if _, err := c.Write([]byte{socksVersion, selectedMethod}); err != nil {
		return err
	}

	if selectedMethod == methodNoAcceptable {
		return ErrNoAcceptableMethod
	}

	return nil
}

func readRequest(c net.Conn) (byte, string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(c, header); err != nil {
		return 0, "", err
	}

	if header[0] != socksVersion {
		return 0, "", fmt.Errorf("%w: got 0x%02x", ErrUnsupportedVersion, header[0])
	}

	if header[2] != reservedByte {
		return 0, "", ErrInvalidReservedByte
	}

	host, err := readAddress(c, header[3])
	if err != nil {
		return 0, "", err
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(c, portBytes); err != nil {
		return 0, "", err
	}

	port := (int(portBytes[0]) << 8) | int(portBytes[1])

	return header[1], net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func readAddress(c net.Conn, addressType byte) (string, error) {
	switch addressType {
	case addressTypeIPv4:
		buf := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", err
		}

		return net.IP(buf).String(), nil
	case addressTypeDomain:
		length := make([]byte, 1)
		if _, err := io.ReadFull(c, length); err != nil {
			return "", err
		}

		domain := make([]byte, int(length[0]))
		if _, err := io.ReadFull(c, domain); err != nil {
			return "", err
		}

		return string(domain), nil
	case addressTypeIPv6:
		buf := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", err
		}

		return net.IP(buf).String(), nil
	default:
		return "", ErrUnsupportedAddrType
	}
}

func writeReply(c net.Conn, replyCode byte, boundAddr net.Addr) error {
	addressType, address, port := buildReplyAddress(boundAddr)

	response := make([]byte, 0, len(address)+6)
	response = append(response, socksVersion, replyCode, reservedByte, addressType)
	response = append(response, address...)
	response = append(response, byte(port>>8), byte(port))

	_, err := c.Write(response)

	return err
}

func buildReplyAddress(boundAddr net.Addr) (byte, []byte, int) {
	tcpAddr, ok := boundAddr.(*net.TCPAddr)
	if !ok {
		return addressTypeIPv4, []byte{0, 0, 0, 0}, 0
	}

	if ip4 := tcpAddr.IP.To4(); ip4 != nil {
		return addressTypeIPv4, ip4, tcpAddr.Port
	}

	if ip6 := tcpAddr.IP.To16(); ip6 != nil {
		return addressTypeIPv6, ip6, tcpAddr.Port
	}

	return addressTypeIPv4, []byte{0, 0, 0, 0}, tcpAddr.Port
}

type closeWriter interface {
	CloseWrite() error
}

func closeWrite(conn net.Conn) error {
	if cw, ok := conn.(closeWriter); ok {
		return cw.CloseWrite()
	}

	return conn.Close()
}
