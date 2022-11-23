package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/sys/unix"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/mdlayher/netlink"
	"github.com/ti-mo/conntrack"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	localIP  = "10.10.10.102"
	httpVer  = 1
	ifName   = "wlp3s0"
	pcapFile = "/tmp/file.pcap"
	runPcap  = false
)

type Conn struct {
	name string
	conn net.Conn

	forResolver bool
	tls         bool
	http2       bool

	bytesSent uint64
	bytesRecv uint64

	httpBodyToRead int64

	req *http.Request
}

func (c *Conn) ConnectionState() tls.ConnectionState {
	if !c.tls {
		return tls.ConnectionState{}
	}
	return c.conn.(*tls.Conn).ConnectionState()
}

func (c *Conn) Read(b []byte) (n int, err error) {
	fmt.Printf("[xxx] Conn %s Read...\n", c.name)
	n, err = c.conn.Read(b)
	fmt.Printf("[xxx] Conn %s Read: %d, %v\n", c.name, n, err)
	//fmt.Printf("[xxx] Conn %s Read: %s\n", c.name, hex.EncodeToString(b[:n]))
	defer func() {
		c.bytesRecv += uint64(n)
	}()
	if err == io.EOF {
		fmt.Printf("[xxx] Conn %s Read: EOF\n", c.name)
		return n, err
	}
	if c.forResolver {
		var p dnsmessage.Parser
		if _, err := p.Start(b); err != nil {
			fmt.Printf("[xxx] Conn %s Read DNS message: %v\n", c.name, err)
		}
		for {
			q, err := p.Question()
			if err == dnsmessage.ErrSectionDone {
				break
			}
			if err != nil {
				fmt.Printf("[xxx] Conn %s Read DNS message: %v\n", c.name, err)
			}
			fmt.Printf("[xxx] Conn %s Read DNS messaage question: %v\n", c.name, q)
		}
		for {
			a, err := p.AnswerHeader()
			if err == dnsmessage.ErrSectionDone {
				break
			}
			if err != nil {
				fmt.Printf("[xxx] Conn %s Read DNS messaage: %v\n", c.name, err)
			}
			fmt.Printf("[xxx] Conn %s Read DNS messaage answer: %v\n", c.name, a)
			var ips []net.IP
			switch a.Type {
			case dnsmessage.TypeA:
				r, err := p.AResource()
				if err != nil {
					panic(err)
				}
				ips = append(ips, r.A[:])
			case dnsmessage.TypeAAAA:
				r, err := p.AAAAResource()
				if err != nil {
					panic(err)
				}
				ips = append(ips, r.AAAA[:])
			}
			fmt.Printf("[xxx] Conn %s Read DNS messaage answer - IPs: %v\n", c.name, ips)
		}
		// More info here: https://pkg.go.dev/golang.org/x/net/dns/dnsmessage#Parser

	} else if c.http2 {
		for m := 0; m < n; {
			// TODO: buffer if even frame header does not fit
			reader := bytes.NewReader(b[m:n])
			frameHeader, err := http2.ReadFrameHeader(reader)
			fmt.Printf("[xxx] Conn %s Read HTTP2 frame header: %v; %v\n", c.name, frameHeader, err)
			frameLength := 9 + int(frameHeader.Length) // including header
			if frameHeader.Type == http2.FrameData && frameHeader.Flags.Has(http2.FlagDataPadded) {
				// https://datatracker.ietf.org/doc/html/rfc7540#section-6.1
				frameLength += int(b[9])
			}
			if n-m < frameLength {
				// TODO: buffering
				fmt.Printf("[xxx] Conn %s Read Not enough bytes available (%d) for full HTTP2 frame\n", c.name, n)
				break
			} else {
				reader.Reset(b[m : m+frameLength])
				framer := http2.NewFramer(nil, reader)
				frame, err := framer.ReadFrame()
				fmt.Printf("[xxx] Conn %s Read HTTP2 frame: %v; %v\n", c.name, frame, err)
				if err == nil && frameHeader.Type == http2.FrameHeaders {
					decoder := hpack.NewDecoder(2048, nil)
					hf, err := decoder.DecodeFull(frame.(*http2.HeadersFrame).HeaderBlockFragment())
					fmt.Printf("[xxx] Conn %s Read HTTP2 headers-frame: %v; %v\n", c.name, hf, err)
				}
				m += frameLength
			}
		}

	} else { // http 1.x
		var m int
		if c.httpBodyToRead > 0 {
			if int64(n) > c.httpBodyToRead {
				m = int(c.httpBodyToRead)
				c.httpBodyToRead = 0
			} else {
				m = n
				c.httpBodyToRead -= int64(n)
			}
			fmt.Printf("[xxx] Conn %s Read HTTP body remain: %d\n", c.name, c.httpBodyToRead)
		}
		if m < n {
			reader := bytes.NewReader(b[m:n])
			bufReader := bufio.NewReader(reader)
			// TODO: maybe replicate what it is doing, but skip readTransfer
			// So just collect header bytes and then skip over body.
			resp, err2 := http.ReadResponse(bufReader, c.req)
			if err2 == nil {
				// TODO: Message length: https://www.rfc-editor.org/rfc/rfc2616#section-4.4
				var headerLen int
				sep := []byte("\r\n\r\n")
				if idx := bytes.Index(b[:n], sep); idx >= 0 {
					headerLen = idx + len(sep)
				}
				c.httpBodyToRead = resp.ContentLength - int64(n-headerLen)
				fmt.Printf("[xxx] Conn %s Read HTTP resp: %v, content len: %d, header len: %d\n", c.name, resp, resp.ContentLength, headerLen)
			} else {
				fmt.Printf("[xxx] Conn %s Read HTTP resp Error: %v\n", c.name, err2)
			}
		}
	}
	return n, err
}

func (c *Conn) Write(b []byte) (n int, err error) {
	fmt.Printf("[xxx] Conn %s Write...\n", c.name)
	n, err = c.conn.Write(b)
	fmt.Printf("[xxx] Conn %s Write: %d, %v\n", c.name, n, err)
	//fmt.Printf("[xxx] Conn %s Write: %s\n", c.name, hex.EncodeToString(b[:n]))
	defer func() {
		c.bytesSent += uint64(n)
	}()
	if c.forResolver {
		var p dnsmessage.Parser
		if _, err := p.Start(b); err != nil {
			fmt.Printf("[xxx] Conn %s Write DNS messaage: %v\n", c.name, err)
		}
		for {
			q, err := p.Question()
			if err == dnsmessage.ErrSectionDone {
				break
			}
			if err != nil {
				fmt.Printf("[xxx] Conn %s Write DNS messaage: %v\n", c.name, err)
			}
			fmt.Printf("[xxx] Conn %s Write DNS messaage question: %v\n", c.name, q)
		}
	} else if c.http2 {
		m := 0
		if c.bytesSent == 0 {
			// https://datatracker.ietf.org/doc/html/rfc7540#section-3.5
			m = 24
		}
		for m < n {
			// TODO: buffer if even frame header does not fit
			reader := bytes.NewReader(b[m:n])
			frameHeader, err := http2.ReadFrameHeader(reader)
			fmt.Printf("[xxx] Conn %s Write HTTP2 frame header: %v; %v\n", c.name, frameHeader, err)
			frameLength := 9 + int(frameHeader.Length) // including header
			if frameHeader.Type == http2.FrameData && frameHeader.Flags.Has(http2.FlagDataPadded) {
				// https://datatracker.ietf.org/doc/html/rfc7540#section-6.1
				frameLength += int(b[9])
			}
			if n-m < frameLength {
				// TODO: buffering
				fmt.Printf("[xxx] Conn %s Write Not enough bytes available (%d) for full HTTP2 frame\n", c.name, n)
				break
			} else {
				reader.Reset(b[m : m+frameLength])
				framer := http2.NewFramer(nil, reader)
				frame, err := framer.ReadFrame()
				fmt.Printf("[xxx] Conn %s Write HTTP2 frame: %v; %v\n", c.name, frame, err)
				if err == nil && frameHeader.Type == http2.FrameHeaders {
					decoder := hpack.NewDecoder(2048, nil)
					hf, err := decoder.DecodeFull(frame.(*http2.HeadersFrame).HeaderBlockFragment())
					fmt.Printf("[xxx] Conn %s Write HTTP2 headers-frame: %v; %v\n", c.name, hf, err)
				}
				m += frameLength
			}
		}
	} else { // http 1.x
		// TODO: Message length: https://www.rfc-editor.org/rfc/rfc2616#section-4.4
		reader := bytes.NewReader(b[:n])
		req, err2 := http.ReadRequest(bufio.NewReader(reader))
		if err2 == nil {
			fmt.Printf("[xxx] Conn %s Write HTTP req: %v\n", c.name, req)
			c.req = req
		} else {
			fmt.Printf("[xxx] Conn %s Write HTTP resp Error: %v\n", c.name, err2)
		}
	}
	return n, err
}

func (c *Conn) Close() error {
	fmt.Printf("[xxx] Conn %s close...\n", c.name)
	err := c.conn.Close()
	fmt.Printf("[xxx] Conn %s close: %v\n", c.name, err)
	fmt.Printf("[xxx] Conn %s bytes sent=%d received=%d\n", c.name, c.bytesSent, c.bytesRecv)
	return err
}

func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

type PacketConn struct {
	*Conn
	packetConn net.PacketConn
}

func (c *PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	fmt.Printf("[xxx] PacketConn %s ReadFrom...\n", c.name)
	n, addr, err = c.packetConn.ReadFrom(p)
	fmt.Printf("[xxx] PacketConn %s ReadFrom: %d, %v, %v\n", c.name, n, addr, err)
	c.bytesRecv += uint64(n)
	return
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	fmt.Printf("[xxx] PacketConn %s WriteTo %v...\n", c.name, addr)
	n, err = c.packetConn.WriteTo(p, addr)
	fmt.Printf("[xxx] PacketConn %s WriteTo %v: %d, %v\n", c.name, addr, n, err)
	c.bytesSent += uint64(n)
	return
}

//--------------------------------------------------------------------------------------

// Dialer ...
// One instance per single HTTP request context.
// We need to make sure that parallel HTTP requests made from the same HTTP client
// use different Dialers.
type Dialer struct {
	nfConn  *conntrack.Conn
	sockets chan inetSocket

	udpConns []connTuple
	tcpConns []connTuple
}

type inetSocket struct {
	fd      int
	dstIP   net.IP
	dstPort uint16
}

type connTuple struct {
	srcIP, dstIP     net.IP
	srcPort, dstPort uint16
}

func (ct connTuple) String() string {
	return fmt.Sprintf("%s:%d->%s:%d", ct.srcIP, ct.srcPort, ct.dstIP, ct.dstPort)
}

func (d *Dialer) init() {
	d.sockets = make(chan inetSocket, 10)
	go d.printAddr()
}

func (d *Dialer) printAddr() {
	// TODO:
	//  1 every x seconds (e.g. 5) get source port (if not yet available) and
	//    update conntracks for every managed connection (where source port is available)
	//  2 when connection is proven closed (not valid orig. FD or reused FD), get source
	//    port (if not yet available) and conntrack (where source port is available)
	//    and remove it from the managed list (close dup fd)
	//  3 when the caller confirms that we have a connection, get source port for every
	//    managed conn without it, update conntrack in every managed connection with source port
	//    Mark the matching connection as *used* (or create a new entry for it if not found),
	//    remove other conns from the managed list.
	//    ALso stop getting source ports (for the used connection), but keep updating
	//    conntrack (?) - maybe only on important change, like TLS done, read/write/close; ctx done
	//    (or also periodically but with longer interval?)
	//
	// - also manage UDP connections (no FD, source port is given) - have event to announce that
	//   DNS requests are done (for a given Dial context)
	// - the main event loop should be able to handle multiple parallel Dials

	var ipv4Timer <-chan time.Time
	activeSocket := inetSocket{fd: -1}
	var period time.Duration
	for {
		select {
		case socket := <-d.sockets:
			if socket.fd == -1 {
				if activeSocket.fd != -1 {
					d.printConnStatus(activeSocket)
					fmt.Printf("[xx] Reading of FD %d is no longer wanted\n", activeSocket.fd)
					err := syscall.Close(activeSocket.fd)
					fmt.Printf("[xx] Closed FD %d: %v\n", activeSocket.fd, err)
				}
				activeSocket.fd = -1
				ipv4Timer = nil // use NewTimer instead to collect garbage
				continue
			}
			if socket.fd == -2 {
				if activeSocket.fd == -1 {
					continue
				}
				fmt.Printf("[xx] Reading FD %d just before it is canceled\n", activeSocket.fd)
				d.printConnStatus(activeSocket)
				err := syscall.Close(activeSocket.fd)
				fmt.Printf("[xx] Closed FD %d: %v\n", activeSocket.fd, err)
				activeSocket.fd = -1
				ipv4Timer = nil // use NewTimer instead to collect garbage
				continue
			}
			if activeSocket.fd != -1 && socket.fd != activeSocket.fd {
				fmt.Printf("[xx] Reading of FD %d is canceled - have new FD %d\n", activeSocket.fd, socket.fd)
				fmt.Printf("[xx] Reading FD %d just before it is canceled\n", activeSocket.fd)
				d.printConnStatus(activeSocket)
				err := syscall.Close(activeSocket.fd)
				fmt.Printf("[xx] Closed FD %d: %v\n", activeSocket.fd, err)
			}
			activeSocket = socket
			period = 1 * time.Second
			ipv4Timer = time.After(period)
			fmt.Printf("[xx] Will read FD %d after %v\n", activeSocket.fd, period)

		case <-ipv4Timer:
			hasSrcPort := d.printConnStatus(activeSocket)
			if !hasSrcPort {
				period *= 2 // exponential backoff
				fmt.Printf("[xx] Don't have src port for FD %d - will retry in %v\n",
					activeSocket.fd, period)
				ipv4Timer = time.After(period)
				continue
			}
			fmt.Printf("[xx] Done reading FD %d - have source port\n", activeSocket.fd)
			activeSocket.fd = -1
			ipv4Timer = nil // use NewTimer instead to collect garbage
			continue
		}
	}
}

func (d *Dialer) ControlFD(network, address string, c syscall.RawConn) error {
	ipStr, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("failed to parse IP address %s", ipStr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}
	var duplicatedFd int
	dupFd := func(fd uintptr) {
		var err error
		duplicatedFd, err = syscall.Dup(int(fd))
		if err != nil {
			fmt.Printf("[x] Control FD - dup FD (%d) err: %v\n", fd, err)
		}
		fmt.Printf("[x] Control FD - duplicated %d to %d\n", fd, duplicatedFd)
		// Can be used if file descriptor is valid:
		flags, err := unix.FcntlInt(fd, unix.F_GETFD, 0)
		fmt.Printf("[x] Control FD - original FD (%d) flags: %v, %v\n", fd, flags, err)
		duplicatedFd2, err := syscall.Dup(int(fd))
		syscall.Close(duplicatedFd2)
		flags, err = unix.FcntlInt(uintptr(duplicatedFd2), unix.F_GETFD, 0)
		fmt.Printf("[x] Control FD - duplicated but closed FD (%d) flags: %v, %v\n", duplicatedFd2, flags, err)
	}
	c.Control(dupFd)
	fmt.Printf("[x] Control FD %s %s: duplicated as %d\n", network, address, duplicatedFd)
	d.sockets <- inetSocket{
		fd:      duplicatedFd,
		dstIP:   ip,
		dstPort: uint16(port),
	}
	return nil
}

func (d *Dialer) ResolverDial(ctx context.Context, network, address string) (net.Conn, error) {
	// TODO: let kernel choose source port, get it using getsockname
	// TODO: support both UPD and TCP
	sPort := rand.Intn(1<<16-1) + 1
	sIP := net.ParseIP(localIP)
	dstHost, dstPort, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	dIP := net.ParseIP(dstHost)
	if dIP == nil {
		return nil, fmt.Errorf("failed to parse dst host %s as IP: ", dstHost)
	}
	dPort, err := strconv.Atoi(dstPort)
	if err != nil {
		return nil, err
	}
	d.udpConns = append(d.udpConns, connTuple{
		srcIP:   sIP,
		dstIP:   dIP,
		srcPort: uint16(sPort),
		dstPort: uint16(dPort),
	})
	// XXX Here we can register DNS connection sIP:sPort -> address (host:port)
	localUDPAddr := &net.UDPAddr{IP: sIP, Port: sPort}
	netDialer := net.Dialer{LocalAddr: localUDPAddr}
	fmt.Printf("[x] Resolver Dial %s:%d -> %s:%s\n", sIP, sPort, network, address)
	conn, err := netDialer.DialContext(ctx, network, address)
	fmt.Printf("[x] Resolver Dial Done %s:%s\n", network, address)
	if err != nil {
		unwrapErrors(err)
	}
	if conn == nil {
		fmt.Printf("[x] Nil resolver connection: %v\n", err.Error())
	} else {
		if packetConn, ok := conn.(net.PacketConn); ok {
			conn = &PacketConn{
				Conn:       &Conn{name: "resolver", conn: conn, forResolver: true},
				packetConn: packetConn,
			}
		} else {
			conn = &Conn{name: "resolver", conn: conn, forResolver: true}
		}
		fmt.Printf("[x] Resolver connection %s:%s: %v <-> %v\n",
			network, address, conn.LocalAddr(), conn.RemoteAddr())
	}
	return conn, err
}

func (d *Dialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	netResolver := net.Resolver{Dial: d.ResolverDial, PreferGo: true, StrictErrors: false}
	/*
		host, _, _ := net.SplitHostPort(address)
		ips, err := netResolver.LookupIP(context.Background(), "ip", host)
		fmt.Printf("[x] Lookup IP %s: %v %v\n", host, ips, err)
	*/
	sIP := net.ParseIP(localIP)
	localTCPAddr := &net.TCPAddr{IP: sIP}
	netDialer := net.Dialer{Resolver: &netResolver, Control: d.ControlFD, LocalAddr: localTCPAddr, Timeout: 3 * time.Second}

	fmt.Printf("[x] Dial %s:%s\n", network, address)
	// Get laddr, netstat and conntrack info before canceling AND closing
	nestedCtx, cancel := context.WithCancel(context.Background())
	go func() {
		<-ctx.Done()
		// Context is closed when request is done - but the connection can remain open and reused
		// for further HTTP requests.
		fmt.Printf("[x] Dial Ctx Done/Canceled %s:%s\n", network, address)
		d.sockets <- inetSocket{fd: -2}
		time.Sleep(time.Second) // TODO: avoid this
		cancel()
	}()
	conn, err := netDialer.DialContext(nestedCtx, network, address)
	fmt.Printf("[x] Dial Done %s:%s\n", network, address)
	// TODO: close all duplicated but later unused FDs, but try to get source port and conntrack
	if err != nil {
		unwrapErrors(err)
	}
	if conn == nil {
		fmt.Printf("[x] Nil connection: %v\n", err.Error())
	} else {
		conn = &Conn{name: "dialer", conn: conn}
		fmt.Printf("[x] Connection %s:%s: %v <-> %v\n",
			network, address, conn.LocalAddr(), conn.RemoteAddr())
	}
	return conn, err
}

func (d *Dialer) DialTLS(ctx context.Context, network, address string, t *http.Transport) (net.Conn, error) {
	netResolver := net.Resolver{Dial: d.ResolverDial, PreferGo: true, StrictErrors: false}
	/*
		host, _, _ := net.SplitHostPort(address)
		ips, err := netResolver.LookupIP(context.Background(), "ip", host)
		fmt.Printf("[x] Lookup IP %s: %v %v\n", host, ips, err)
	*/
	sIP := net.ParseIP(localIP)
	localTCPAddr := &net.TCPAddr{IP: sIP}
	netDialer := net.Dialer{Resolver: &netResolver, Control: d.ControlFD, LocalAddr: localTCPAddr, Timeout: 3 * time.Second}

	fmt.Printf("[x] Dial %s:%s\n", network, address)
	// Get laddr, netstat and conntrack info before canceling AND closing
	nestedCtx, cancel := context.WithCancel(context.Background())
	go func() {
		<-ctx.Done()
		fmt.Printf("[x] Dial Ctx Done/Canceled %s:%s\n", network, address)
		d.sockets <- inetSocket{fd: -2}
		time.Sleep(time.Second) // TODO: avoid this
		cancel()
	}()
	tcpConn, err := netDialer.DialContext(nestedCtx, network, address)
	fmt.Printf("[x] Dial (TCP only) Done %s:%s\n", network, address)
	// TODO: close all duplicated but later unused FDs, but try to get source port and conntrack
	if err != nil {
		unwrapErrors(err)
	}
	if tcpConn == nil {
		fmt.Printf("[x] Nil TCP connection: %v\n", err.Error())
		return tcpConn, err
	}

	fmt.Printf("[x] TCP Connection %s:%s: %v <-> %v\n",
		network, address, tcpConn.LocalAddr(), tcpConn.RemoteAddr())

	// TLS handshake
	var serverName string
	if serverName, _, err = net.SplitHostPort(address); err != nil {
		fmt.Printf("[x] Nil TCP connection: %v\n", err.Error())
		_ = tcpConn.Close()
		return nil, err
	}
	tlsConfig := t.TLSClientConfig.Clone()
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = serverName
	}
	fmt.Printf("[x] TLS config: %+v\n", tlsConfig)
	tlsConn := tls.Client(tcpConn, tlsConfig)
	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		var certErr x509.CertificateInvalidError
		if errors.As(err, &certErr) {
			fmt.Printf("[x] TLS handshake server cert: %+v; %+v\n",
				certErr.Cert.Subject, certErr.Cert.Issuer)
		}
		var hostnameErr x509.HostnameError
		if errors.As(err, &hostnameErr) {
			fmt.Printf("[x] TLS handshake server cert: %+v; %+v\n",
				hostnameErr.Certificate.Subject, hostnameErr.Certificate.Issuer)
		}
		var unknownAuthErr x509.UnknownAuthorityError
		if errors.As(err, &unknownAuthErr) {
			fmt.Printf("[x] TLS handshake server cert: %+v; %+v\n",
				unknownAuthErr.Cert.Subject, unknownAuthErr.Cert.Issuer)
		}
		fmt.Printf("[x] TLS handshake failed: %v\n", err.Error())
		unwrapErrors(err)
		_ = tcpConn.Close()
		return nil, err
	}
	tlsState := tlsConn.ConnectionState()
	for i, peer := range tlsState.PeerCertificates {
		fmt.Printf("[x] Peer [%d]: %+v; %+v\n", i, peer.Subject, peer.Issuer)
	}
	fmt.Printf("[x] Negotiated protocol: %s\n", tlsState.NegotiatedProtocol)
	fmt.Printf("[x] Cipher suite: %v\n", tlsState.CipherSuite)
	fmt.Printf("[x] ServerName: %s\n", tlsState.ServerName)
	fmt.Printf("[x] TLS Connection %s:%s: %v\n",
		network, address, tlsConn.ConnectionState())
	http2 := tlsState.NegotiatedProtocol == "h2"
	if !http2 {
		// XXX We should return tls.Conn and wrap it later
		return &Conn{name: "dialer", conn: tlsConn, tls: true, http2: http2}, err
	}
	return tlsConn, err
}

// TODO: conntrack also for UDP
// TODO: also for IPv6
func (d *Dialer) printConnStatus(socket inetSocket) bool {
	var srcPort uint16
	var srcIP net.IP
	sa, err := syscall.Getsockname(socket.fd)
	fmt.Printf("[x] Getsockname (%d) %v %v\n", socket.fd, sa, err)
	if sa != nil {
		if laddr4, ok := sa.(*syscall.SockaddrInet4); ok {
			fmt.Printf("[x] LAddr4 (%d) %+v\n", socket.fd, laddr4)
			srcPort = uint16(laddr4.Port)
			srcIP = laddr4.Addr[:]
		}
	}
	sa, err = syscall.Getpeername(socket.fd)
	fmt.Printf("[x] Getpeername (%d) %v %v\n", socket.fd, sa, err)
	if sa != nil {
		if raddr4, ok := sa.(*syscall.SockaddrInet4); ok {
			fmt.Printf("[x] RAddr4 (%d) %+v\n", socket.fd, raddr4)
		}
	}
	if srcPort != 0 && srcIP != nil {
		d.tcpConns = append(d.tcpConns, connTuple{
			srcIP:   srcIP,
			dstIP:   socket.dstIP,
			srcPort: srcPort,
			dstPort: socket.dstPort,
		})
		flow, err := d.nfConn.Get(conntrack.Flow{
			TupleOrig: conntrack.Tuple{
				IP: conntrack.IPTuple{
					SourceAddress:      srcIP,
					DestinationAddress: socket.dstIP,
				},
				Proto: conntrack.ProtoTuple{
					Protocol:        syscall.IPPROTO_TCP,
					SourcePort:      srcPort,
					DestinationPort: socket.dstPort,
				},
			},
		})
		if err != nil {
			fmt.Printf("[x] Conntrack Get (%v) failed: %v\n", socket, err)
		} else {
			// https://elixir.bootlin.com/linux/v5.10.19/source/net/netfilter/nf_conntrack_proto_tcp.c#L51
			tcpStates := []string{
				"NONE",
				"SYN_SENT",
				"SYN_RECV",
				"ESTABLISHED",
				"FIN_WAIT",
				"CLOSE_WAIT",
				"LAST_ACK",
				"TIME_WAIT",
				"CLOSE",
				"SYN_SENT2",
			}
			fmt.Printf("[x] Conntrack (%d) %+v; %+v; %s\n", socket.fd, flow,
				*flow.ProtoInfo.TCP, tcpStates[int(flow.ProtoInfo.TCP.State)])
		}
	}
	return srcPort != 0
}

func unwrapErrors(err error) {
	for ; err != nil; err = errors.Unwrap(err) {
		fmt.Printf("[x] Error %T: %s\n", err, err.Error())
	}
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	var pcapCtx context.Context
	var cancelPcap context.CancelFunc
	var packets []gopacket.Packet
	if runPcap {
		// sudo tcpdump -dd "icmp or arp or tcp or udp"
		bpfFilter := []pcap.BPFInstruction{
			{Code: 0x28, Jt: 0, Jf: 0, K: 0x0000000c},
			{Code: 0x15, Jt: 0, Jf: 3, K: 0x00000800},
			{Code: 0x30, Jt: 0, Jf: 0, K: 0x00000017},
			{Code: 0x15, Jt: 9, Jf: 0, K: 0x00000001},
			{Code: 0x15, Jt: 8, Jf: 7, K: 0x00000006},
			{Code: 0x15, Jt: 7, Jf: 0, K: 0x00000806},
			{Code: 0x15, Jt: 0, Jf: 7, K: 0x000086dd},
			{Code: 0x30, Jt: 0, Jf: 0, K: 0x00000014},
			{Code: 0x15, Jt: 4, Jf: 0, K: 0x00000006},
			{Code: 0x15, Jt: 0, Jf: 2, K: 0x0000002c},
			{Code: 0x30, Jt: 0, Jf: 0, K: 0x00000036},
			{Code: 0x15, Jt: 1, Jf: 0, K: 0x00000006},
			{Code: 0x15, Jt: 0, Jf: 1, K: 0x00000011},
			{Code: 0x6, Jt: 0, Jf: 0, K: 0x00040000},
			{Code: 0x6, Jt: 0, Jf: 0, K: 0x00000000},
		}
		// https://pkg.go.dev/github.com/google/gopacket/pcap#hdr-PCAP_Timeouts
		handle, err := pcap.OpenLive(ifName, 2048, false, pcap.BlockForever)
		if err != nil {
			panic(err)
			return
		}
		defer handle.Close()
		err = handle.SetBPFInstructionFilter(bpfFilter)
		if err != nil {
			panic(err)
		}
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetsCh := packetSource.Packets()
		pcapCtx, cancelPcap = context.WithCancel(context.Background())
		go func() {
			for {
				select {
				case <-pcapCtx.Done():
					fmt.Printf("Packet capture is done\n")
					return
				case p := <-packetsCh:
					packets = append(packets, p)
				}
			}
		}()
	}

	nfConn, err := conntrack.Dial(&netlink.Config{})
	if err != nil {
		panic(err)
	}

	dialer := &Dialer{nfConn: nfConn}
	dialer.init()
	transport := &http.Transport{}
	//transport.DisableKeepAlives = true
	// Called for every connection (dialed or reused) before making HTTP request.
	tlsNextProto := map[string]func(authority string, c *tls.Conn) http.RoundTripper{}
	if false {
		// XXX This is only needed to get TLS state into HTTP response (should we care?)
		// But this does not work anyway...
		// And a bunch of other things are broken, see tryPutIdleConn in http/transport.go.
		http1RoundTripper := func(authority string, c *tls.Conn) http.RoundTripper {
			t1Copy := *transport
			t1Copy.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				fmt.Printf("[x] Dial TLS H1 %s:%s\n", network, addr)
				conn := &Conn{name: "dialer", conn: c, tls: true, http2: false}
				return conn, nil
			}
			return &t1Copy
		}
		h1APLN := []string{"", "http/1.1", "http/1.0"}
		for _, h1 := range h1APLN {
			tlsNextProto[h1] = http1RoundTripper
		}
	}
	if httpVer == 2 {
		transport.ForceAttemptHTTP2 = true
		transport.TLSClientConfig = &tls.Config{
			NextProtos: []string{http2.NextProtoTLS, "http/1.1", "http/1.0"},
		}
		// Necessary to upgrade from HTTP 1.x transport to HTTP 2 transport.
		tlsNextProto[http2.NextProtoTLS] = func(authority string, c *tls.Conn) http.RoundTripper {
			// used only as config for t2
			t1Config := &http.Transport{
				DisableKeepAlives:     transport.DisableKeepAlives,
				DisableCompression:    transport.DisableCompression,
				IdleConnTimeout:       transport.IdleConnTimeout,
				ResponseHeaderTimeout: transport.ResponseHeaderTimeout,
			}
			t2, err := http2.ConfigureTransports(t1Config)
			if err != nil {
				panic(err)
			}
			// force call to DialTLSContext where we wrap tls.Conn with out connection
			// TODO: check if this is OK and that it does not break anything
			t2.ConnPool = nil
			t2.DialTLSContext = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				fmt.Printf("[x] Dial TLS H2 %s:%s\n", network, addr)
				conn := &Conn{name: "dialer", conn: c, tls: true, http2: true}
				return conn, nil
			}
			return t2
		}
	} else {
		transport.TLSClientConfig = &tls.Config{
			NextProtos: []string{"http/1.1", "http/1.0"},
		}
	}
	transport.TLSNextProto = tlsNextProto
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.Dial(ctx, network, addr)
	}
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialTLS(ctx, network, addr, transport)
	}

	transport.RoundTrip = nil

	client := &http.Client{Transport: transport}
	client.Timeout = 60 * time.Second

	for i := 0; i < 1; i++ {
		req, err := http.NewRequest("GET", "https://www.google.com/", nil)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		req = req.WithContext(context.Background())

		fmt.Printf("Starting HTTP request\n")
		resp, err := client.Do(req)
		fmt.Printf("HTTP request done: %v; %+v, %v\n", resp, resp.TLS, err)

		if resp != nil && resp.Body != nil {
			/*
				buf := make([]byte, 512)
				_, err := resp.Body.Read(buf)
				if err != nil {
					break
				}
				fmt.Println(string(buf[:n]))
			*/
			if _, err := io.Copy(ioutil.Discard, resp.Body); err != nil {
				panic(err)
			}
		}

		if resp != nil && resp.Body != nil {
			fmt.Println(resp.Body.Close())
		}
	}

	time.Sleep(3 * time.Second)

	fmt.Printf("UDP \"connections\" %v\n", dialer.udpConns)
	fmt.Printf("TCP connections %v\n", dialer.tcpConns)

	if runPcap {
		cancelPcap()
		f, _ := os.Create(pcapFile)
		w := pcapgo.NewWriter(f)
		w.WriteFileHeader(65536, layers.LinkTypeEthernet) // new file, must do this.
		var filteredOut int
		for _, packet := range packets {
			//fmt.Printf("Captured packet: %s\n", packet.String())
			// TODO: filter packets (keep ARPs, IMCPs, but filter UDP and TCP not from this app)
			// TODO: filter it using conntrack - it can be NATed (use TupleOrig, TupleReply)
			if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
				ipL, _ := layer.(*layers.IPv4)
				if layer := packet.Layer(layers.LayerTypeUDP); layer != nil {
					udpL, _ := layer.(*layers.UDP)
					var keep bool
					for _, udpConn := range dialer.udpConns {
						if udpConn.srcIP.Equal(ipL.SrcIP) && udpConn.dstIP.Equal(ipL.DstIP) &&
							udpConn.srcPort == uint16(udpL.SrcPort) && udpConn.dstPort == uint16(udpL.DstPort) {
							keep = true
							break
						}
						if udpConn.srcIP.Equal(ipL.DstIP) && udpConn.dstIP.Equal(ipL.SrcIP) &&
							udpConn.srcPort == uint16(udpL.DstPort) && udpConn.dstPort == uint16(udpL.SrcPort) {
							keep = true
							break
						}
					}
					if !keep {
						filteredOut++
						continue
					}
				} else if layer := packet.Layer(layers.LayerTypeTCP); layer != nil {
					tcpL, _ := layer.(*layers.TCP)
					var keep bool
					for _, tcpConn := range dialer.tcpConns {
						if tcpConn.srcIP.Equal(ipL.SrcIP) && tcpConn.dstIP.Equal(ipL.DstIP) &&
							tcpConn.srcPort == uint16(tcpL.SrcPort) && tcpConn.dstPort == uint16(tcpL.DstPort) {
							keep = true
							break
						}
						if tcpConn.srcIP.Equal(ipL.DstIP) && tcpConn.dstIP.Equal(ipL.SrcIP) &&
							tcpConn.srcPort == uint16(tcpL.DstPort) && tcpConn.dstPort == uint16(tcpL.SrcPort) {
							keep = true
							break
						}
					}
					if !keep {
						filteredOut++
						continue
					}
				} else {
					fmt.Printf("ARP/ICMP packet? (IP, but neither UDP, nor TCP) %s\n", packet.String())
				}
			} else {
				fmt.Printf("ARP/ICMP packet? (no IP) %s\n", packet.String())
			}
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}
		f.Close()
		fmt.Printf("Captured %d packets, filtered out %d packets, pcap written to %s\n",
			len(packets), filteredOut, pcapFile)
	}

	httptrace.WithClientTrace()

	// Notes:
	//
	// * If the underlying Dial has timeout we have no chance to obtain stats before it is closed
	//    - probably not the case in EVE
	//    - RESOLVED: dup the packet, get the stats from conntrack
	// * If the TCP is closed with reset then ... same as above
	// * How to have separate Dial contexts for parallel request coming from the same HTTP client
	//     - probably Dial could be creating dialer
	//     - and the overall context will be for the HTTP client
	//     - with opts like: TLS config, HTTP2?, TraceHTTPTraffic, GetConntrack, etc.
	//     - with methods like:
	//         * StartTask(name, description)
	//         * EndTask() *HttpDiag
	// * http client is not an interface, how to enable tracing when used in 3rd party downloaders?
	//     - http tracing not needed
	// * with ENOTAVAIL (cannot bind) - Dial will make 3 attempts
	// * measure speed ?
	// * measure latency for handshakes (TCP - between Control and Dial done)
	// * measure data transfer received/sent (headers, body, total)
	// * can we get number of retransmissions for a socket? - No
	// * the socket monitor could use select to see when socket state changes, then get sockname
	//     - or maybe just read getsockname after connection is done or timeouted
	//     - but probably it is best to try to get it asynchronously after some time (to not lose conntrack)
	//     - also collect conntrack AFTER connection is done (but not too late after or we will lose it)
	// * log read, writes duration + timestamp (since the start of connection)
	// * parse HTTP requests and responses only if enabled
	// * print some (or all?) http header fields, like Referer
	// * HTTP/2 support
	// * what if HTTP header does not fit into one read - support that
	// * HTTP/1 message length: https://www.rfc-editor.org/rfc/rfc2616#section-4.4
	//    - also support chunks
	//    - also listing multiparts? Probably no
	// * in our dialer we could trigger the resolution and try IPs sequentially (just to stay safe)
	//     - No, lets use the original Dialer
	// * Add connection state to conntrack entry returned by vishvananda
	//    - or consider using: https://github.com/ti-mo/conntrack
	//    - https://elixir.bootlin.com/linux/v5.10.19/source/net/netfilter/nf_conntrack_proto_tcp.c#L51
	// * Support combining diag output with packet trace (keep packets for traced conns + ARPs + ICMPs)
	//    - capture only headers up to L4: 18b (ethernet) + Max(24b,40b) (IPv4, IPv6 - excluding extensions) + Max(60b,8b) (TCP, UDP) = 118b (~ 2^7 bytes)
	//    - packet capture could be done automatically during onboarding (/register API + first /config requests)
	//    - also on-demand (for zedcloud ping or some other req/url)
	//    - also once in a while during longer connectivity outage (e.g. once per day for a /config request)
	//       - but only for the latest DPC
	//       - should be configurable and can be disabled (by default enabled with 1 day period)
	// * Keep (only the last) HTTP+packet trace information in /persist (for /register or /config)
	//    - directory structure (will be all compressed and put under /persist as one archive):
	//    -  http-trace-<timestamp>/
	//          trace.json (all info except for packet capture)
	//          pcap/
	//            task-0/
	//              eth0.pcap
	//              eth1.pcap
	//            task-1/
	//              ...
	//    - at least until the latest (could be newly obtained) DPC starts working (at last or again)
	//    - for post mortem analysis
	//    - but preferably permanently (because they may USB-override device in another location to get connectivity and debug the issue)
	//    - later we may think if and how to publish to zedcloud
	//    - how would they obtain it:
	//       - if not onboarded: using USB diag
	//       - if onboarded: - ssh/edge-view from another network and download
	//                       - connect via console and download,
	//                       - move device to staging area, USB-override network config, use one of the methods above to download
	//
	// * HTTP+packet trace should contain (defined by protobuf - for the LOC sake mostly):
	//     (caller info) - from some package under pkg/pillar
	//      - start time (when TraceStart() was called - starts Go routine), endTime (TraceEnd() Trace)
	//      - (optional) DPC trace (to see which one was applied at each point of the trace and how status was changing)
	//         - list of: DPC key (source + timestamp), DPC status, DPC timestamp, testing?
	//         - requires DNS subscription (will be disabled if not available)
	//      - tasks (or regions, but I prefer task)
	//        - without active task nothing is traced? - let's always have some task active
	//              - maybe TraceStart could take "first task name+args"
	//        - TaskStart(name, args)
	//        - start time, end time
	//        - task name (download image XYZ, get device config, etc.)
	//        - task args (string->string map, e.g. ifname:eth0, image-name:8.12.0)
	//        - (optional) packet capture (likely saved in separate files in most cases - LOC could get it as bytes)
	//           - filtered - keep ARP, ICMP, UDP & TCP matching any connection in any task (current + previous)
	//           - separate trace for every management interface (may need to add/del during runtime - requires DNS sub)
	//           - packet size limited to some number of bytes (128 by default ?, configurable)
	//     (httptrace info) - (/libs) not sure if it will be more readable if separated per task (but how to trace reused connection between tasks?)
	//      - for every Dial
	//        - event ID
	//        - ref. task ID
	//        - dial begin + end time, context close time
	//        - destination address
	//        - proxy config
	//      - DNS trace (one entry for every DNS query):
	//        - event ID
	//        - ref. task ID + ref. dial ID
	//        - bind time, close time, 5-tuple, error(-s unwrapped?)
	//        - total send + received upper-layer bytes
	//        - (optional) conntrack (captured-at time, tuple after NAT, mark, flags, packet/byte counters),
	//        - (optional) socket trace (see "socket trace" under TCP trace below)
	//        - (optional) DNS trace - array of:
	//           - DNS request: send time, questions, socket write events (IDs)
	//           - DNS response: recv. time, DNS answers, socket read events (IDs)
	//      - TCP trace (connections - established and attempted):
	//        - event ID
	//        - ref. task ID + ref. dial ID
	//        - handshake start + done time, conn close time, 5-tuple, error(-s unwrapped?)
	//        - (optional) conntrack (captured at time, tuple after NAT, mark, flags, packet/byte counters, TCP state),
	//		  - was it reused?
	//           - this is implicit - there will be simply new HTTP request
	//           - we can have separate tasks and there tcp connection would reappear in the next one (with reused=true, or reused=conn/event-ID)
	//           - or simply events related to this connection (read, write, HTTP req/resp, would reference their task ID and reference the connection ID)
	//           - to test it: https://golang.cafe/blog/how-to-reuse-http-connections-in-go.html;
	//                         https://stackoverflow.com/questions/57683132/turning-off-connection-pool-for-go-http-client
	//           - better yet: after ClearTrace re-add TCP trace entry (+ Dial entry) with Reused=true if it is taken from Idle connection pool
	//                 - need to remember trace of idle connections (eve after ClearTrace) - removed by Close()
	//        - total send + received L4 payload bytes (part of socket trace, see below)
	//        - (optional) socket trace (of upper-layer data - above TLS) - array of:
	//           - read entry: event ID, ref. task ID, recv begin+end time, len, error(-s unwrapped?)
	//           - write entry: event ID, ref. task ID, write begin+end time, len, error(-s unwrapped?)
	//           - TODO: how to split CONNECT from trace inside then created TLS tunnel
	//               - well we cannot really read the inside of TLS tunnel in HTTP 1.x, only in HTTP 2.x
	//               - actually in HTTP 2.x we cannot read the CONNECT
	//      - TLS trace - there could be also TLS inside for proxy (multiple TLSes for one TCP conn)
	//           - ref. TCP conn ID (or dial ID)
	//           - handshake start time, handshake done time, error(-s unwrapped?)
	//           - for every (known) peer cert in the chain: subject, issuer, validity time range (NotBefore, NotAfter)
	//           - negotiated proto (ALPN), Server Name (SNI), negotiated CipherSuite (https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-4)
	//      - (optional) HTTP 1.x trace - array of:
	//        - request: event ID (needed ?), ref. task ID, ref. TCP conn ID (or dial ID),
	//                   method, URI, HTTP version, headers (all, or only some? - what about sensitive info?),
	//                   message body length (determined - https://www.rfc-editor.org/rfc/rfc2616#section-4.4; for multipart see: https://www.rfc-editor.org/rfc/rfc2046#section-5.1),
	//                   socket write events (ref. IDs)
	//        - response: event ID (needed ?), ref. task ID, ref. TCP conn ID (or dial ID),
	//                    status code, HTTP version, headers (all, or only some? - what about sensitive info?),
	//                    message body length (determined - https://www.rfc-editor.org/rfc/rfc2616#section-4.4; for multipart see: https://www.rfc-editor.org/rfc/rfc2046#section-5.1),
	//                    socket read events (ref. IDs)
	//      - (optional) HTTP 2.x trace - array of (TODO: read RFC):
	//        - frame info - event ID, ref. task ID, ref. TCP conn ID (or dial ID),
	//                       direction (client->server or the opposite), frame type, stream ID, length,
	//                       headers (for header frames; some or all? - what about sensitive info>)
	//                       socket read/write events (ref. IDs)
	//
	//   - Use event IDs (or some kind of IDs to reference between events within HTTP trace)
	//        - only unique within a trace
	//        - can be task-number/some-integer (or separate)
	//   - or maybe lets create a HTTP client wrapper with methods:
	//      - GetTrace() HTTPTrace, ClearTrace(), Close (stop tracing)
	//      - the concept of tasks will be in pillar, not in httptrace
	//   - print to logs as JSON formatted - easier to pretty print
	//   - TODO: see how hard is it to get using BPF:
	//             - ack dup count (problems in server->client dir) + retransmission count (problems in client->server dir)
	//             - last recv ack + sack (i.e. where it got stuck on the client->server direction)
	//             - last sent ack + sack (i.e. where it got stuck on the server->client direction)
	//             - see: https://blog.devgenius.io/how-to-write-ebpf-programs-with-golang-933d58fc5dba
	//             - see: https://manpages.ubuntu.com/manpages/bionic/man8/tcpretrans-perf.8.html
	//
	// Some important notes:
	// (HTTP 1.1)
	//  In general, HTTP treats a multipart message-body no differently than
	//   any other media type: strictly as payload. The one exception is the
	//   "multipart/byteranges" type (appendix 19.2) when it appears in a 206
	//   (Partial Content) response, which will be interpreted by some HTTP
	//   caching mechanisms as described in sections 13.5.4 and 14.16. In all
	//   other cases, an HTTP user agent SHOULD follow the same or similar
	//   behavior as a MIME user agent would upon receipt of a multipart type.
	//   The MIME header fields within each body-part of a multipart message-
	//   body do not have any significance to HTTP beyond that defined by
	//   their MIME semantics.
	//
	//   In the interest of robustness, servers SHOULD ignore any empty
	//   line(s) received where a Request-Line is expected. In other words, if
	//   the server is reading the protocol stream at the beginning of a
	//   message and receives a CRLF first, it should ignore the CRLF.
	//
	// - TODO: test with proxies
	//          - very likely we are screwed - inside the connection there is TLS encrypted traffic (for https dest)
	//          - our custom TLS dialer is not called :((((
	// - TODO: upgrade from HTTP 1.x to HTTP 2 (response code 101)
}
