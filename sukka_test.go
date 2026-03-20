package sukka

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestHandleConnInvalidVersion(t *testing.T) {
	client, errCh := startHandleConn(t, &Server{})
	defer client.Close()
	setDeadline(t, client)

	if _, err := client.Write([]byte{0x04, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	err := waitHandleConn(t, errCh)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("expected unsupported version error, got: %v", err)
	}
}

func TestHandleConnNoAcceptableMethod(t *testing.T) {
	client, errCh := startHandleConn(t, &Server{})
	defer client.Close()
	setDeadline(t, client)

	if _, err := client.Write([]byte{socksVersion, 0x01, methodUsernamePassword}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	response := readN(t, client, 2)
	if !bytes.Equal(response, []byte{socksVersion, methodNoAcceptable}) {
		t.Fatalf("unexpected negotiation response: %v", response)
	}

	err := waitHandleConn(t, errCh)
	if !errors.Is(err, ErrNoAcceptableMethod) {
		t.Fatalf("expected no acceptable method error, got: %v", err)
	}
}

func TestHandleConnUnsupportedCommand(t *testing.T) {
	client, errCh := startHandleConn(t, &Server{})
	defer client.Close()
	setDeadline(t, client)

	performHandshake(t, client)

	request := buildIPv4Request(t, "127.0.0.1:80", 0x02)
	if _, err := client.Write(request); err != nil {
		t.Fatalf("write request: %v", err)
	}

	if reply := readReplyCode(t, client); reply != replyCommandNotSupported {
		t.Fatalf("expected command-not-supported reply, got: 0x%02x", reply)
	}

	err := waitHandleConn(t, errCh)
	if !errors.Is(err, ErrUnsupportedCommand) {
		t.Fatalf("expected unsupported command error, got: %v", err)
	}
}

func TestHandleConnUnsupportedAddressType(t *testing.T) {
	client, errCh := startHandleConn(t, &Server{})
	defer client.Close()
	setDeadline(t, client)

	performHandshake(t, client)

	if _, err := client.Write([]byte{socksVersion, commandConnect, 0x00, 0x09}); err != nil {
		t.Fatalf("write request: %v", err)
	}

	if reply := readReplyCode(t, client); reply != replyAddressNotSupported {
		t.Fatalf("expected address-not-supported reply, got: 0x%02x", reply)
	}

	err := waitHandleConn(t, errCh)
	if !errors.Is(err, ErrUnsupportedAddrType) {
		t.Fatalf("expected unsupported address type error, got: %v", err)
	}
}

func TestHandleConnInvalidRequestReservedByte(t *testing.T) {
	client, errCh := startHandleConn(t, &Server{})
	defer client.Close()
	setDeadline(t, client)

	performHandshake(t, client)

	if _, err := client.Write([]byte{socksVersion, commandConnect, 0x01, addressTypeIPv4}); err != nil {
		t.Fatalf("write request: %v", err)
	}

	if reply := readReplyCode(t, client); reply != replyGeneralFailure {
		t.Fatalf("expected general-failure reply, got: 0x%02x", reply)
	}

	err := waitHandleConn(t, errCh)
	if !errors.Is(err, ErrInvalidReservedByte) {
		t.Fatalf("expected invalid reserved byte error, got: %v", err)
	}
}

func TestHandleConnConnectAndRelay(t *testing.T) {
	targetAddr, closeTarget := startEchoServer(t)
	defer closeTarget()

	client, errCh := startHandleConn(t, &Server{})
	defer client.Close()
	setDeadline(t, client)

	performHandshake(t, client)

	request := buildIPv4Request(t, targetAddr, commandConnect)
	if _, err := client.Write(request); err != nil {
		t.Fatalf("write connect request: %v", err)
	}

	if reply := readReplyCode(t, client); reply != replySucceeded {
		t.Fatalf("expected success reply, got: 0x%02x", reply)
	}

	payload := []byte("hello through proxy")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	got := readN(t, client, len(payload))
	if !bytes.Equal(got, payload) {
		t.Fatalf("unexpected relayed payload: got %q want %q", got, payload)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}

	if err := waitHandleConn(t, errCh); err != nil {
		t.Fatalf("expected clean shutdown, got: %v", err)
	}
}

func TestReadRequestDomainAddress(t *testing.T) {
	client, serverSide := net.Pipe()
	defer client.Close()
	defer serverSide.Close()

	requestErrCh := make(chan error, 1)
	var gotCommand byte
	var gotDestination string

	go func() {
		var err error
		gotCommand, gotDestination, err = readRequest(serverSide)
		requestErrCh <- err
	}()

	request := []byte{socksVersion, commandConnect, reservedByte, addressTypeDomain, byte(len("example.com"))}
	request = append(request, []byte("example.com")...)
	request = append(request, 0x00, 0x50)

	if _, err := client.Write(request); err != nil {
		t.Fatalf("write request: %v", err)
	}

	if err := waitErr(t, requestErrCh); err != nil {
		t.Fatalf("read request: %v", err)
	}

	if gotCommand != commandConnect {
		t.Fatalf("unexpected command: got 0x%02x want 0x%02x", gotCommand, commandConnect)
	}

	if gotDestination != "example.com:80" {
		t.Fatalf("unexpected destination: got %q want %q", gotDestination, "example.com:80")
	}
}

func TestReadRequestIPv6Address(t *testing.T) {
	client, serverSide := net.Pipe()
	defer client.Close()
	defer serverSide.Close()

	requestErrCh := make(chan error, 1)
	var gotCommand byte
	var gotDestination string

	ip := net.ParseIP("2001:db8::1").To16()
	if ip == nil {
		t.Fatal("parse IPv6 address")
	}

	go func() {
		var err error
		gotCommand, gotDestination, err = readRequest(serverSide)
		requestErrCh <- err
	}()

	request := []byte{socksVersion, commandConnect, reservedByte, addressTypeIPv6}
	request = append(request, ip...)
	request = append(request, 0x01, 0xbb)

	if _, err := client.Write(request); err != nil {
		t.Fatalf("write request: %v", err)
	}

	if err := waitErr(t, requestErrCh); err != nil {
		t.Fatalf("read request: %v", err)
	}

	if gotCommand != commandConnect {
		t.Fatalf("unexpected command: got 0x%02x want 0x%02x", gotCommand, commandConnect)
	}

	wantDestination := net.JoinHostPort(net.IP(ip).String(), "443")
	if gotDestination != wantDestination {
		t.Fatalf("unexpected destination: got %q want %q", gotDestination, wantDestination)
	}
}

func TestServerListenAddr(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{name: "default", want: defaultListenAddr},
		{name: "configured", addr: "127.0.0.1:2080", want: "127.0.0.1:2080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{Addr: tt.addr}
			if got := s.listenAddr(); got != tt.want {
				t.Fatalf("listenAddr() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestServerDialConnUsesCustomDial(t *testing.T) {
	dialErr := errors.New("dial failed")
	s := &Server{
		Dial: func(network, address string) (net.Conn, error) {
			if network != "tcp" {
				t.Fatalf("unexpected network: %q", network)
			}

			if address != "example.com:80" {
				t.Fatalf("unexpected address: %q", address)
			}

			return nil, dialErr
		},
	}

	if _, err := s.dialConn("tcp", "example.com:80"); !errors.Is(err, dialErr) {
		t.Fatalf("expected dial error, got: %v", err)
	}
}

func TestServerServeNilListener(t *testing.T) {
	if err := new(Server).Serve(nil); !errors.Is(err, ErrNilListener) {
		t.Fatalf("expected nil listener error, got: %v", err)
	}
}

func startHandleConn(t *testing.T, s *Server) (net.Conn, <-chan error) {
	t.Helper()

	if s.Logger == nil {
		s.Logger = log.New(io.Discard, "", 0)
	}

	client, serverSide := net.Pipe()
	errCh := make(chan error, 1)

	go func() {
		errCh <- s.handleConn(serverSide)
	}()

	return client, errCh
}

func performHandshake(t *testing.T, c net.Conn) {
	t.Helper()

	if _, err := c.Write([]byte{socksVersion, 0x01, methodNoAuthRequired}); err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	response := readN(t, c, 2)
	if !bytes.Equal(response, []byte{socksVersion, methodNoAuthRequired}) {
		t.Fatalf("unexpected handshake response: %v", response)
	}
}

func buildIPv4Request(t *testing.T, destination string, command byte) []byte {
	t.Helper()

	host, portStr, err := net.SplitHostPort(destination)
	if err != nil {
		t.Fatalf("split host/port: %v", err)
	}

	ip4 := net.ParseIP(host).To4()
	if ip4 == nil {
		t.Fatalf("destination is not ipv4: %q", destination)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	request := []byte{socksVersion, command, 0x00, addressTypeIPv4}
	request = append(request, ip4...)
	request = append(request, byte(port>>8), byte(port))

	return request
}

func readReplyCode(t *testing.T, c net.Conn) byte {
	t.Helper()

	header := readN(t, c, 4)
	if header[0] != socksVersion {
		t.Fatalf("unexpected reply version: 0x%02x", header[0])
	}

	var addrLen int
	switch header[3] {
	case addressTypeIPv4:
		addrLen = net.IPv4len
	case addressTypeIPv6:
		addrLen = net.IPv6len
	case addressTypeDomain:
		domainLen := readN(t, c, 1)
		addrLen = int(domainLen[0])
	default:
		t.Fatalf("unexpected reply address type: 0x%02x", header[3])
	}

	_ = readN(t, c, addrLen+2)

	return header[1]
}

func readN(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()

	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}

	return buf
}

func waitHandleConn(t *testing.T, errCh <-chan error) error {
	t.Helper()

	return waitErr(t, errCh)
}

func waitErr(t *testing.T, errCh <-chan error) error {
	t.Helper()

	select {
	case err := <-errCh:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for handleConn")
		return nil
	}
}

func setDeadline(t *testing.T, c net.Conn) {
	t.Helper()

	if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
}

func startEchoServer(t *testing.T) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo server: %v", err)
	}

	done := make(chan struct{})

	go func() {
		defer close(done)

		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		_, _ = io.Copy(conn, conn)
	}()

	cleanup := func() {
		_ = ln.Close()

		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("timeout closing echo server")
		}
	}

	return ln.Addr().String(), cleanup
}
