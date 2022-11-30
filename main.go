/*
-> Prepare network namespace:

sudo ip netns add httptrace
sudo ip -n httptrace link set dev lo up
sudo ip link add httptrace-in type veth peer name httptrace-out
sudo ip link set httptrace-in netns httptrace
sudo ip -n httptrace addr add 192.168.88.2/24 dev httptrace-in
sudo ip addr add 192.168.88.1/24 dev httptrace-out
sudo ip -n httptrace link set httptrace-in up
sudo ip link set httptrace-out up
sudo ip -n httptrace route add default dev httptrace-in via 192.168.88.1
sudo iptables -t filter -A FORWARD -i httptrace-out -j ACCEPT
sudo iptables -t filter -A FORWARD -o httptrace-out -j ACCEPT

-> Consider creating a separate resolv.conf for this network namespace:

sudo mkdir -p /etc/netns/httptrace
sudo sh -c 'echo "nameserver 8.8.8.8" > /etc/netns/httptrace/resolv.conf'

-> To test conntrack with NAT:

sudo ip netns exec httptrace iptables -t nat -A POSTROUTING -o httptrace-in -j MASQUERADE
sudo ip -n httptrace addr add 192.168.99.1/24 dev lo
// and change localIP (constant, see below) to 192.168.99.1

-> Without locally running proxy it is also necessary to setup NAT:

sudo iptables -t nat -A POSTROUTING -o <out-iface> -j MASQUERADE

-> Run httptrace:

go build -v .
sudo ip netns exec httptrace ./httptrace
*/
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/http2"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/mdlayher/netlink"
	"github.com/ti-mo/conntrack"
)

const (
	destURL   = "https://www.google.com/"
	localIP   = /*"192.168.88.2"*/ "192.168.99.1"
	httpVer   = 2  // 1 or 2
	proxy     = "" //https://10.10.10.101:9091"
	proxyCert = "-----BEGIN CERTIFICATE-----\nMIIDVTCCAj2gAwIBAgIUPGtlx1k08RmWd9RxiCKTXYnAUkIwDQYJKoZIhvcNAQEL\nBQAwOjETMBEGA1UEAwwKemVkZWRhLmNvbTELMAkGA1UEBhMCVVMxFjAUBgNVBAcM\nDVNhbiBGcmFuY2lzY28wHhcNMjIwOTA3MTcwMDE0WhcNMzIwNjA2MTcwMDE0WjA6\nMRMwEQYDVQQDDAp6ZWRlZGEuY29tMQswCQYDVQQGEwJVUzEWMBQGA1UEBwwNU2Fu\nIEZyYW5jaXNjbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALQsi7IG\nM8KApujL71MJXbuPQNn/g+RItQeehaFRcqcCcpFW4k1YveMNdf5HReKlAfufFtaa\nIF368t33UlleblopLM8m8r9Ev1sSJOS1yYgU1HABjyw54LXBqT4tAf0xjlRaLn4L\nQBUAS0TTywTppGXtNwXpxqdDuQdigNskqzEFaGI52IQezfGt7L2CeeJ/YJNcbImR\neCXMPwTatUHLLE29Qv8GQQfy7TpCXdXVLvQAyfZJi7lY7DjPqBab5ocnVTRcEpKz\nFwH2+KTokQkU1UF614IveRF3ZOqqmrQvy1AdSvekFLIz2uP7xsfy3I3HNQcPJ4DI\n5vNzBaE/hF5xK40CAwEAAaNTMFEwHQYDVR0OBBYEFPxOB5cxsf89x6KdFSTTFV2L\nwta1MB8GA1UdIwQYMBaAFPxOB5cxsf89x6KdFSTTFV2Lwta1MA8GA1UdEwEB/wQF\nMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAFXqCJuq4ifMw3Hre7+X23q25jOb1nzd\n8qs+1Tij8osUC5ekD21x/k9g+xHvacoJIOzsAmpAPSnwXKMnvVdAeX6Scg1Bvejj\nTdXfNEJ7jcvDROUNjlWYjwiY+7ahDkj56nahwGjjUQdgCCzRiSYPOq6N1tRkn97a\ni6+jB8DnTSDnv5j8xiPDbWJ+nv2O1NNsoHS91UrTqkVXxNItrCdPPh21hzrTJxs4\noSf4wbaF5n3E2cPpSAaXBEyxBdXAqUCIhP0q9/pgBTYuJ+eW467u4xWqUVi4iBtN\nwVfYelYC2v03Rn433kv624oJDQ7MM5bDUv3nqPtkUys0ARwxs8tQCgg=\n-----END CERTIFICATE-----"
	ifName    = "httptrace-in"
	reqCount  = 1
	pcapFile  = "/tmp/httptrace.pcap"
	runPcap   = true
)

type Conn struct {
	name string
	conn net.Conn

	forResolver bool

	bytesSent uint64
	bytesRecv uint64
}

func (c *Conn) Read(b []byte) (n int, err error) {
	c.traceReadBegin(b)
	n, err = c.conn.Read(b)
	c.traceReadEnd(b, n, nil, err)
	return n, err
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.traceWriteBegin(b, nil)
	n, err = c.conn.Write(b)
	c.traceWriteEnd(n, err)
	return n, err
}

func (c *Conn) traceReadBegin(b []byte) {
	fmt.Printf("[CONN] Conn %s Read (max) %d bytes...\n", c.name, len(b))
}

func (c *Conn) traceReadEnd(b []byte, n int, addr net.Addr, err error) {
	fmt.Printf("[CONN] Conn %s Read: %d, %v, %v\n", c.name, n, addr, err)
	c.bytesRecv += uint64(n)
	if err == io.EOF {
		fmt.Printf("[CONN] Conn %s Read: EOF\n", c.name)
	}
	if c.forResolver {
		var p dnsmessage.Parser
		header, err := p.Start(b)
		fmt.Printf("[CONN] Conn %s Read DNS message header: %+v; %v\n", c.name, header, err)
		if err != nil {
			fmt.Printf("[CONN] Conn %s Read DNS message: %v\n", c.name, err)
		}
		_ = p.SkipAllQuestions()
		for {
			a, err := p.AnswerHeader()
			if err == dnsmessage.ErrSectionDone {
				break
			}
			if err != nil {
				fmt.Printf("[CONN] Conn %s Read DNS message AnswerHeader error: %v\n", c.name, err)
			}
			fmt.Printf("[CONN] Conn %s Read DNS message answer: %v\n", c.name, a)
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
			fmt.Printf("[CONN] Conn %s Read DNS message answer - IPs: %v\n", c.name, ips)
		}
		// More info here: https://pkg.go.dev/golang.org/x/net/dns/dnsmessage#Parser
	}
}

func (c *Conn) traceWriteBegin(b []byte, addr net.Addr) {
	fmt.Printf("[CONN] Conn %s Write %d bytes to %v...\n", c.name, len(b), addr)
	if c.forResolver {
		var p dnsmessage.Parser
		header, err := p.Start(b)
		if err != nil {
			fmt.Printf("[CONN] Conn %s Write DNS message: %v\n", c.name, err)
		}

		fmt.Printf("[CONN] Write %s Write DNS message header: %+v; %v\n", c.name, header, err)
		for {
			q, err := p.Question()
			if err == dnsmessage.ErrSectionDone {
				break
			}
			if err != nil {
				fmt.Printf("[CONN] Conn %s Write DNS message: %v\n", c.name, err)
			}
			fmt.Printf("[CONN] Conn %s Write DNS message question: %v\n", c.name, q)
		}
	}
}

func (c *Conn) traceWriteEnd(n int, err error) {
	fmt.Printf("[CONN] Conn %s Wrote: %d, %v\n", c.name, n, err)
	defer func() {
		c.bytesSent += uint64(n)
	}()
}

func (c *Conn) Close() error {
	fmt.Printf("[CONN] Conn %s close...\n", c.name)
	err := c.conn.Close()
	fmt.Printf("[CONN] Conn %s close: %v\n", c.name, err)
	fmt.Printf("[CONN] Conn %s bytes sent=%d received=%d\n", c.name, c.bytesSent, c.bytesRecv)
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
	c.traceReadBegin(p)
	n, addr, err = c.packetConn.ReadFrom(p)
	c.traceReadEnd(p, n, addr, err)
	return
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.traceWriteBegin(p, addr)
	n, err = c.packetConn.WriteTo(p, addr)
	c.traceWriteEnd(n, err)
	return
}

//--------------------------------------------------------------------------------------

type HTTPBody struct {
	Name        string
	WrappedBody io.ReadCloser
	Length      int
}

func (b *HTTPBody) Read(p []byte) (n int, err error) {
	fmt.Printf("[HTTP] %s Read\n", b.Name)

	n, err = b.WrappedBody.Read(p)
	b.Length += n
	if err == io.EOF {
		fmt.Printf("[HTTP] %s has body of size: %d\n", b.Name, b.Length)
	}
	return n, err
}

// TODO: define only when WrappedBody implements it.
// e.g. (from request.go):
//
//	if _, ok := r.(WriterTo); ok {
//	   return nopCloserWriterTo{r}
//	}
func (b *HTTPBody) Write(p []byte) (n int, err error) {
	fmt.Printf("[HTTP] %s Write\n", b.Name)

	return b.WrappedBody.(io.Writer).Write(p)
}

func (b *HTTPBody) Close() (err error) {
	var buf [32]byte
	var n int
	for err == nil {
		n, err = b.WrappedBody.Read(buf[:])
		b.Length += n
	}
	closeErr := b.WrappedBody.Close()
	if err != nil && err != io.EOF {
		return err
	}
	fmt.Printf("[HTTP] %s has body of size: %d\n", b.Name, b.Length)
	return closeErr
}

//--------------------------------------------------------------------------------------

// Transport : transport for HTTP client with tracing
// One instance per single HTTP request context.
// We need to make sure that parallel HTTP requests made from the same HTTP client
// use different Dialers.
type Transport struct {
	nfConn  *conntrack.Conn
	sockets chan inetSocket

	wrappedT *http.Transport

	udpConns []connTuple
	tcpConns []connTuple
}

type inetSocket struct {
	fd      int
	dstIP   net.IP
	dstPort uint16
	proto   uint8
}

type connTuple struct {
	srcIP, dstIP     net.IP
	srcPort, dstPort uint16
	conntrackFlow    *conntrack.Flow
}

func (ct connTuple) String() string {
	return fmt.Sprintf("%s:%d->%s:%d", ct.srcIP, ct.srcPort, ct.dstIP, ct.dstPort)
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	fmt.Printf("[TRANSP] HTTP request: %v, size=%d\n", req, req.ContentLength)
	ctx := req.Context()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			fmt.Printf("[HTTPTRACE] GetConn: %v\n", hostPort)
		},
		GotConn: func(connInfo httptrace.GotConnInfo) {
			fmt.Printf("[HTTPTRACE] GotConn: reused=%t, was-idle=%t, idle-time=%v, "+
				"conn=%v->%v\n",
				connInfo.Reused, connInfo.WasIdle, connInfo.IdleTime,
				connInfo.Conn.LocalAddr(), connInfo.Conn.RemoteAddr())
		},
		PutIdleConn: func(err error) {
			fmt.Printf("[HTTPTRACE] PutIdleConn: %v\n", err)
		},
		GotFirstResponseByte: func() {
			fmt.Printf("[HTTPTRACE] GotFirstResponseByte\n")

		},
		Got100Continue: func() {
			fmt.Printf("[HTTPTRACE] Got100Continue\n")
		},
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			fmt.Printf("[HTTPTRACE] Got1xxResponse: %d; %v\n", code, header)
			return nil
		},
		TLSHandshakeStart: func() {
			fmt.Printf("[HTTPTRACE] TLSHandshakeStart\n")
		},
		TLSHandshakeDone: func(tlsState tls.ConnectionState, err error) {
			fmt.Printf("[HTTPTRACE] TLSHandshakeDone: %v, %v\n", tlsState, err)
			if err != nil {
				var certErr x509.CertificateInvalidError
				if errors.As(err, &certErr) {
					fmt.Printf("[HTTPTRACE] TLS handshake server cert: %+v; %+v; "+
						"valid since %v until %v\n",
						certErr.Cert.Subject, certErr.Cert.Issuer,
						certErr.Cert.NotBefore, certErr.Cert.NotAfter)
				}
				var hostnameErr x509.HostnameError
				if errors.As(err, &hostnameErr) {
					fmt.Printf("[HTTPTRACE] TLS handshake server cert: %+v; %+v; "+
						"valid since %v until %v\n",
						hostnameErr.Certificate.Subject, hostnameErr.Certificate.Issuer,
						hostnameErr.Certificate.NotBefore, hostnameErr.Certificate.NotAfter)
				}
				var unknownAuthErr x509.UnknownAuthorityError
				if errors.As(err, &unknownAuthErr) {
					fmt.Printf("[HTTPTRACE] TLS handshake CA cert: %+v; %+v; "+
						"valid since %v until %v\n",
						unknownAuthErr.Cert.Subject, unknownAuthErr.Cert.Issuer,
						unknownAuthErr.Cert.NotBefore, unknownAuthErr.Cert.NotAfter)
				}
				fmt.Printf("[HTTPTRACE] TLS handshake failed: %v\n", err.Error())
				unwrapErrors(err)
			} else {
				for i, peer := range tlsState.PeerCertificates {
					fmt.Printf("[HTTPTRACE] Peer [%d]: %+v; %+v; valid since %v until %v\n",
						i, peer.Subject, peer.Issuer, peer.NotBefore, peer.NotAfter)
				}
				fmt.Printf("[HTTPTRACE] Negotiated protocol: %s\n", tlsState.NegotiatedProtocol)
				fmt.Printf("[HTTPTRACE] Cipher suite: %v\n", tlsState.CipherSuite)
				fmt.Printf("[HTTPTRACE] ServerName: %s\n", tlsState.ServerName)
			}
		},
		WroteHeaders: func() {
			fmt.Printf("[HTTPTRACE] WroteHeaders\n")
		},
		Wait100Continue: func() {
			fmt.Printf("[HTTPTRACE] Wait100Continue\n")
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			fmt.Printf("[HTTPTRACE] WroteRequest: %+v\n", info)
		},
	})
	req = req.WithContext(ctx)
	if req.Body != nil {
		req.Body = &HTTPBody{Name: "Request", WrappedBody: req.Body}
	}
	resp, err := t.wrappedT.RoundTrip(req)
	fmt.Printf("[TRANSP] HTTP response: %v; %v\n", resp, err)
	if resp.Body != nil {
		resp.Body = &HTTPBody{Name: "Response", WrappedBody: resp.Body}
	}
	return resp, err
}

func (t *Transport) init() {
	t.sockets = make(chan inetSocket, 10)
	t.wrappedT = &http.Transport{
		DialContext: t.dial,
		// DisableKeepAlives: true,
	}
	if httpVer == 2 {
		err := http2.ConfigureTransport(t.wrappedT)
		if err != nil {
			panic(err)
		}
	}
	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			panic(err)
		}
		t.wrappedT.Proxy = http.ProxyURL(proxyURL)
		if proxyCert != "" {
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM([]byte(proxyCert))
			t.wrappedT.TLSClientConfig = &tls.Config{
				RootCAs: caCertPool,
				// InsecureSkipVerify: true,
			}
		}
	}
	go t.monitorConnections()
}

func (t *Transport) monitorConnections() {
	// TODO:
	//  1 every x seconds (e.g. 5) get source port (if not yet available) and
	//    update conntracks for every managed connection (where source port is available)
	//  2 when connection is proven closed (not valid orig. FD or reused FD or Conn.Close called),
	//    get source port (if not yet available) and conntrack (where source port is available)
	//    and remove it from the managed list (close dup fd)
	//  3 when the caller confirms that we have a connection, get source port for every
	//    managed conn without it, update conntrack in every managed connection with source port
	//    Mark the matching connection as *used* (or create a new entry for it if not found),
	//    remove other conns from the managed list.
	//    Also stop getting source ports (for the used connection), but keep updating
	//    conntrack (?) - maybe only on important change, like TLS done, read/write/close; ctx done
	//    (or also periodically but with longer interval?)
	//
	// - also manage UDP connections - have event to announce that DNS requests are done
	//   (for a given Dial context)
	// - the main event loop should be able to handle multiple parallel Dials

	var ipv4Timer <-chan time.Time
	activeSocket := inetSocket{fd: -1}
	var period time.Duration
	for {
		select {
		case socket := <-t.sockets:
			if socket.fd == -1 {
				if activeSocket.fd != -1 {
					t.printConnStatus(activeSocket)
					fmt.Printf("[MONITOR] Monitoring of FD %d is no longer wanted\n", activeSocket.fd)
					err := syscall.Close(activeSocket.fd)
					fmt.Printf("[MONITOR] Closed duplicated FD %d: %v\n", activeSocket.fd, err)
				}
				activeSocket.fd = -1
				ipv4Timer = nil // use NewTimer instead to collect garbage
				continue
			}
			if activeSocket.fd != -1 && socket.fd != activeSocket.fd {
				fmt.Printf("[MONITOR] Monitoring of FD %d is canceled - have new FD %d\n", activeSocket.fd, socket.fd)
				fmt.Printf("[MONITOR] Reading FD %d just before it is canceled\n", activeSocket.fd)
				t.printConnStatus(activeSocket)
				err := syscall.Close(activeSocket.fd)
				fmt.Printf("[MONITOR] Closed duplicated FD %d: %v\n", activeSocket.fd, err)
			}
			activeSocket = socket
			period = 1 * time.Second
			ipv4Timer = time.After(period)
			fmt.Printf("[MONITOR] Will read FD %d after %v\n", activeSocket.fd, period)

		case <-ipv4Timer:
			hasSrcPort := t.printConnStatus(activeSocket)
			if !hasSrcPort {
				period *= 2 // exponential backoff
				fmt.Printf("[MONITOR] Don't have src port for FD %d - will retry in %v\n",
					activeSocket.fd, period)
				ipv4Timer = time.After(period)
				continue
			}
			fmt.Printf("[MONITOR] Done reading FD %d - have source port\n", activeSocket.fd)
			activeSocket.fd = -1
			ipv4Timer = nil // TODO: use NewTimer instead to collect garbage
			continue
		}
	}
}

func (t *Transport) controlFD(network, address string, conn syscall.RawConn) error {
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
	var proto uint8
	proto = syscall.IPPROTO_TCP
	if strings.HasPrefix(network, "udp") {
		proto = syscall.IPPROTO_UDP
	}
	var duplicatedFd int
	dupFd := func(fd uintptr) {
		var err error
		duplicatedFd, err = syscall.Dup(int(fd))
		if err != nil {
			fmt.Printf("[MONITOR] Control FD - dup FD (%d) err: %v\n", fd, err)
		}
		fmt.Printf("[MONITOR] Control FD - duplicated %d to %d\n", fd, duplicatedFd)
		// Can be used to check if file descriptor is valid:
		/*
			flags, err := unix.FcntlInt(fd, unix.F_GETFD, 0)
			fmt.Printf("[x] Control FD - original FD (%d) flags: %v, %v\n", fd, flags, err)
			duplicatedFd2, err := syscall.Dup(int(fd))
			syscall.Close(duplicatedFd2)
			flags, err = unix.FcntlInt(uintptr(duplicatedFd2), unix.F_GETFD, 0)
			fmt.Printf("[x] Control FD - duplicated but closed FD (%d) flags: %v, %v\n", duplicatedFd2, flags, err)
		*/
	}
	conn.Control(dupFd)
	fmt.Printf("[MONITOR] Control FD %s %s: duplicated as %d\n", network, address, duplicatedFd)
	t.sockets <- inetSocket{
		fd:      duplicatedFd,
		dstIP:   ip,
		dstPort: uint16(port),
		proto:   proto,
	}
	return nil
}

func (t *Transport) resolverDial(ctx context.Context, network, address string) (net.Conn, error) {
	sIP := net.ParseIP(localIP)
	// TODO: support both UPD and TCP
	localUDPAddr := &net.UDPAddr{IP: sIP}
	netDialer := net.Dialer{Control: t.controlFD, LocalAddr: localUDPAddr}

	fmt.Printf("[TRANSP] Resolver Dial %s:%s\n", network, address)
	go func() {
		<-ctx.Done()
		// Context is closed when request is done - but the connection can remain open
		// and reused for further HTTP requests.
		fmt.Printf("[TRANSP] Resolver Dial Ctx Done/Canceled %s:%s\n", network, address)
	}()
	conn, err := netDialer.DialContext(ctx, network, address)
	fmt.Printf("[TRANSP] Resolver Dial Done %s:%s with err: %v\n", network, address, err)
	if err != nil {
		unwrapErrors(err)
	}
	// close all duplicated but later unused FDs, but try to get source port and conntrack
	t.sockets <- inetSocket{fd: -1}

	if conn == nil {
		fmt.Printf("[TRANSP] Resolver Dial returned Nil resolver connection: %v\n", err.Error())
	} else {
		connName := fmt.Sprintf("%s->%s", conn.LocalAddr(), conn.RemoteAddr())
		if packetConn, ok := conn.(net.PacketConn); ok {
			conn = &PacketConn{
				Conn:       &Conn{name: connName, conn: conn, forResolver: true},
				packetConn: packetConn,
			}
		} else {
			conn = &Conn{name: connName, conn: conn, forResolver: true}
		}
		fmt.Printf("[TRANSP] Resolver connection %s:%s: %v <-> %v\n",
			network, address, conn.LocalAddr(), conn.RemoteAddr())
	}
	return conn, err
}

func (t *Transport) dial(ctx context.Context, network, address string) (net.Conn, error) {
	netResolver := net.Resolver{Dial: t.resolverDial, PreferGo: true, StrictErrors: false}
	sIP := net.ParseIP(localIP)
	localTCPAddr := &net.TCPAddr{IP: sIP}
	netDialer := net.Dialer{Resolver: &netResolver, Control: t.controlFD,
		LocalAddr: localTCPAddr, Timeout: 10 * time.Second}

	fmt.Printf("[TRANSP] Dial %s:%s\n", network, address)
	go func() {
		<-ctx.Done()
		// Context is closed when request is done - but the connection can remain open
		// and reused for further HTTP requests.
		fmt.Printf("[TRANSP] Dial Ctx Done/Canceled %s:%s\n", network, address)
	}()
	// XXX: Multiple resolverDial can be triggered in parallel! (typically one for A and another for AAAA).
	// In this PoC this is not handled well because monitorConnections() is only capable of handling
	// one socket at a time.
	conn, err := netDialer.DialContext(ctx, network, address)
	fmt.Printf("[TRANSP] Dial Done %s:%s with err: %v\n", network, address, err)
	if err != nil {
		unwrapErrors(err)
	}
	// close all duplicated but later unused FDs, but try to get source port and conntrack
	t.sockets <- inetSocket{fd: -1}

	if conn == nil {
		fmt.Printf("[TRANSP] Dial returned Nil connection: %v\n", err.Error())
	} else {
		connName := fmt.Sprintf("%s->%s", conn.LocalAddr(), conn.RemoteAddr())
		conn = &Conn{name: connName, conn: conn}
		fmt.Printf("[TRANSP] TCP Connection %s:%s: %v <-> %v\n",
			network, address, conn.LocalAddr(), conn.RemoteAddr())
	}
	return conn, err
}

// TODO: also for IPv6
func (t *Transport) printConnStatus(socket inetSocket) bool {
	var srcPort uint16
	var srcIP net.IP
	sa, err := syscall.Getsockname(socket.fd)
	fmt.Printf("[MONITOR] Getsockname (%d) %v %v\n", socket.fd, sa, err)
	if sa != nil {
		if laddr4, ok := sa.(*syscall.SockaddrInet4); ok {
			fmt.Printf("[MONITOR] LAddr4 (%d) %+v\n", socket.fd, laddr4)
			srcPort = uint16(laddr4.Port)
			srcIP = laddr4.Addr[:]
		}
	}
	if socket.proto == syscall.IPPROTO_TCP {
		sa, err = syscall.Getpeername(socket.fd)
		fmt.Printf("[MONITOR] Getpeername (%d) %v %v\n", socket.fd, sa, err)
		if sa != nil {
			if raddr4, ok := sa.(*syscall.SockaddrInet4); ok {
				fmt.Printf("[MONITOR] RAddr4 (%d) %+v\n", socket.fd, raddr4)
			}
		}
	}
	if srcPort != 0 && srcIP != nil {
		var conntrackFlow *conntrack.Flow
		flow, err := t.nfConn.Get(conntrack.Flow{
			TupleOrig: conntrack.Tuple{
				IP: conntrack.IPTuple{
					SourceAddress:      srcIP,
					DestinationAddress: socket.dstIP,
				},
				Proto: conntrack.ProtoTuple{
					Protocol:        socket.proto,
					SourcePort:      srcPort,
					DestinationPort: socket.dstPort,
				},
			},
		})
		if err != nil {
			fmt.Printf("[MONITOR] Conntrack Get (%v) failed: %v\n", socket, err)
		} else {
			conntrackFlow = &flow
			switch socket.proto {
			case syscall.IPPROTO_TCP:
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
				fmt.Printf("[MONITOR] TCP Conntrack (%d) %+v; %+v; %s\n", socket.fd, flow,
					*flow.ProtoInfo.TCP, tcpStates[int(flow.ProtoInfo.TCP.State)])
			case syscall.IPPROTO_UDP:
				fmt.Printf("[MONITOR] UDP Conntrack (%d) %+v\n", socket.fd, flow)
			}
		}
		switch socket.proto {
		case syscall.IPPROTO_TCP:
			t.tcpConns = append(t.tcpConns, connTuple{
				srcIP:         srcIP,
				dstIP:         socket.dstIP,
				srcPort:       srcPort,
				dstPort:       socket.dstPort,
				conntrackFlow: conntrackFlow,
			})
		case syscall.IPPROTO_UDP:
			t.udpConns = append(t.udpConns, connTuple{
				srcIP:         srcIP,
				dstIP:         socket.dstIP,
				srcPort:       srcPort,
				dstPort:       socket.dstPort,
				conntrackFlow: conntrackFlow,
			})
		}
	}
	return srcPort != 0
}

//--------------------------------------------------------------------------------------

func unwrapErrors(err error) {
	for ; err != nil; err = errors.Unwrap(err) {
		fmt.Printf("[ERR] Error %T: %s\n", err, err.Error())
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
	transport := &Transport{nfConn: nfConn}
	transport.init()

	client := &http.Client{Transport: transport}
	client.Timeout = 60 * time.Second

	//http.Transport

	for i := 0; i < reqCount; i++ {
		ctx := context.Background()
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
			GotConn: func(connInfo httptrace.GotConnInfo) {
				fmt.Printf("[USER] GotConn: %v\n", connInfo)
			},
			TLSHandshakeDone: func(tlsState tls.ConnectionState, err error) {
				fmt.Printf("[USER] TLSHandshakeDone: %v, %v\n", tlsState, err)
			},
		})
		req, err := http.NewRequestWithContext(ctx, "GET", destURL, nil)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Printf("Starting HTTP request: %v\n", req)
		resp, err := client.Do(req)
		fmt.Printf("HTTP request done: %v; %v\n", resp, err)

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

	fmt.Printf("UDP \"connections\" %v\n", transport.udpConns)
	fmt.Printf("TCP connections %v\n", transport.tcpConns)

	if runPcap {
		cancelPcap()
		f, _ := os.Create(pcapFile)
		w := pcapgo.NewWriter(f)
		w.WriteFileHeader(65536, layers.LinkTypeEthernet) // new file, must do this.
		var filteredOut int
		for _, packet := range packets {
			getConnAddrs := func(tuple connTuple) (srcIP, dstIP net.IP, srcPort, dstPort uint16) {
				if tuple.conntrackFlow != nil && tuple.conntrackFlow.TupleReply.Proto.DestinationPort != 0 {
					//  Conntrack {Status:CONFIRMED|SRC_NAT|SRC_NAT_DONE|DST_NAT_DONE
					//             TupleOrig:<udp, Src: 192.168.99.1:42542, Dst: 10.10.10.1:53>
					//             TupleReply:<udp, Src: 10.10.10.1:53, Dst: 192.168.88.2:42542>
					//             TupleMaster:<0, Src: <nil>:0, Dst: <nil>:0>
					//             Mark:0 Use:2 SynProxy:{ISN:0 ITS:0 TSOff:0}}
					srcIP = tuple.conntrackFlow.TupleReply.IP.DestinationAddress
					dstIP = tuple.conntrackFlow.TupleReply.IP.SourceAddress
					srcPort = tuple.conntrackFlow.TupleReply.Proto.DestinationPort
					dstPort = tuple.conntrackFlow.TupleReply.Proto.SourcePort
				} else {
					srcIP = tuple.srcIP
					dstIP = tuple.dstIP
					srcPort = tuple.srcPort
					dstPort = tuple.dstPort
				}
				return
			}
			if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
				ipL, _ := layer.(*layers.IPv4)
				if layer := packet.Layer(layers.LayerTypeUDP); layer != nil {
					udpL, _ := layer.(*layers.UDP)
					var keep bool
					for _, udpConn := range transport.udpConns {
						srcIP, dstIP, srcPort, dstPort := getConnAddrs(udpConn)
						// request direction:
						if srcIP.Equal(ipL.SrcIP) && dstIP.Equal(ipL.DstIP) &&
							srcPort == uint16(udpL.SrcPort) && dstPort == uint16(udpL.DstPort) {
							keep = true
							break
						}
						// reply direction:
						if srcIP.Equal(ipL.DstIP) && dstIP.Equal(ipL.SrcIP) &&
							srcPort == uint16(udpL.DstPort) && dstPort == uint16(udpL.SrcPort) {
							keep = true
							break
						}
					}
					if !keep {
						filteredOut++
						fmt.Printf("Filtered packet: %s\n", packet.String())
						continue
					}
				} else if layer := packet.Layer(layers.LayerTypeTCP); layer != nil {
					tcpL, _ := layer.(*layers.TCP)
					var keep bool
					for _, tcpConn := range transport.tcpConns {
						srcIP, dstIP, srcPort, dstPort := getConnAddrs(tcpConn)
						// request direction:
						if srcIP.Equal(ipL.SrcIP) && dstIP.Equal(ipL.DstIP) &&
							srcPort == uint16(tcpL.SrcPort) && dstPort == uint16(tcpL.DstPort) {
							keep = true
							break
						}
						// reply direction:
						if srcIP.Equal(ipL.DstIP) && dstIP.Equal(ipL.SrcIP) &&
							srcPort == uint16(tcpL.DstPort) && dstPort == uint16(tcpL.SrcPort) {
							keep = true
							break
						}
					}
					if !keep {
						filteredOut++
						fmt.Printf("Filtered packet: %s\n", packet.String())
						continue
					}
				} else {
					fmt.Printf("ICMP packet? (IP, but neither UDP, nor TCP) %s\n", packet.String())
				}
			} else {
				fmt.Printf("ARP packet? (no IP) %s\n", packet.String())
			}
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}
		f.Close()
		fmt.Printf("Captured %d packets, filtered out %d packets, pcap written to %s\n",
			len(packets), filteredOut, pcapFile)
	}

	// Notes:
	//
	// * If the underlying Dial has timeout we have no chance to obtain stats before it is closed
	//    - probably not the case in EVE
	//    - RESOLVED: dup the packet, get the stats from conntrack
	// * If the TCP is closed with reset then ... same as above
	// * with ENOTAVAIL (cannot bind) - Dial will make 3 attempts
	// * measure latency for handshakes (TCP - between Control and Dial done)
	// * measure data transfer received/sent (headers, body, total)
	// * can we get number of retransmissions for a socket? - No
	// * the socket monitor could use select to see when socket state changes, then get sockname
	//     - or maybe just read getsockname after connection is done or timeouted
	//     - but probably it is best to try to get it asynchronously after some time (to not lose conntrack)
	//     - also collect conntrack AFTER connection is done (but not too late after or we will lose it)
	// * log socket read, writes duration + timestamp (since the start of connection)
	// * log HTTP requests and responses only if enabled
	//     - include some (or all?) http header fields, like Referer
	// * HTTP/2 support (just give option to enable and prefer it)
	// * in our dialer we could trigger the resolution and try IPs sequentially (just to stay safe)
	//     - No, lets use the original Dialer
	// * Add connection state to conntrack entry returned by vishvananda
	//    - or consider using: https://github.com/ti-mo/conntrack  (YES)
	//    - https://elixir.bootlin.com/linux/v5.10.19/source/net/netfilter/nf_conntrack_proto_tcp.c#L51
	// * Support combining diag output with packet trace (keep packets for traced conns + ARPs + ICMPs)
	//    - done by diag microservice
	//    - will include (1 or more?) /ping requests to the controller + google.com
	//    - capture only headers up to L4: 18b (ethernet) + Max(24b,40b) (IPv4, IPv6 - excluding extensions) + Max(60b,8b) (TCP, UDP) = 118b (~ 2^7 bytes)
	//         - also limit the overall size of the capture (to say 1MB)
	//    - packet capture could be done automatically before onboarding
	//       - after that only once per day if the latest DPC has not worked once in the last 24hrs
	//       - should be configurable and can be disabled (by default enabled with 1 day period)
	//    - also on-demand (for zedcloud ping or some other req/url) from LOC
	//    - keep only the last N (e.g. 5) http traces
	//    - also when doing tracing, also log the trace (maybe with some summary about packets - no let's keep that in /persist)
	//    - directory structure (will be all compressed and put under /persist as one archive):
	//        http-trace-<timestamp>/
	//          test1-name/ (e.g. ping-controller)
	//            trace.json (all info except for packet capture)
	//            pcap/
	//              eth0.pcap
	//              eth1.pcap
	//              ...
	//          test2-name/ (e.g. get-google.com)
	//              ...
	//    - for post mortem analysis
	//    - later we may think if and how to publish to zedcloud
	//    - how would they obtain it:
	//       - if not onboarded: using USB "diag" stick
	//       - if onboarded: - ssh/edge-view from another network and download
	//                       - connect via console and download,
	//                       - move device to a staging area, USB-override network config, use one of the methods above to download
	//
	// * HTTP+packet trace should contain (defined by protobuf - for the LOC sake mostly - but it will be in libs?!):
	//    * info collected by diag (HTTP trace from /libs would be embedded)
	//      - DPC trace (to see which one was applied at each point of the trace and how status was changing)
	//         - list of: DPC key (source + timestamp), DPC status, DPC timestamp, was-being-tested?
	//      - (optional) packet capture (likely saved in separate files - LOC could get it as bytes)
	//         - filtered - keep ARP, ICMP, UDP & TCP matching any connection in any task (current + previous)
	//         - separate trace for every management interface
	//         - packet size limited to some number of bytes (128 by default ?, configurable)
	//    * libs/httptrace
	//      - time when client was created (the other timestamps can be offsets)
	//          - add method to get start time / current offset
	//      - time when trace was collected
	//      - description (for the reader to know what the trace is for)
	//         - set when the trace is collected
	//      - for every Dial
	//        - dial ID
	//        - ref. established tcp connection ID
	//        - dial begin + end time, context close time
	//        - destination address
	//        - proxy config, static source IP (if set, otherwise nil)
	//      - DNS trace (one entry for every DNS query):
	//        - ref. dial ID
	//        - bind time, close time, 5-tuple, error(-s unwrapped?)
	//        - total send + received upper-layer bytes
	//        - (optional) conntrack (captured-at time, tuple after NAT, mark, flags, packet/byte counters),
	//        - (optional) socket trace (see "socket trace" under TCP trace below)
	//        - (optional) DNS trace - array of:
	//           - DNS request: send time, questions, socket write event (index; only if socket trace is enabled)
	//           - DNS response: recv. time, DNS answers, socket read event (index; only if socket trace is enabled)
	//      - TCP trace (TCP connections - established and attempted):
	//        - tcp conn ID
	//        - ref. dial ID
	//        - handshake start + done time, conn close time, 5-tuple, error(-s unwrapped?)
	//        - (optional) conntrack (captured at time, tuple after NAT, mark, flags, packet/byte counters, TCP state),
	//		  - was it reused?
	//           - after ClearTrace re-add TCP trace entry (+ Dial entry) with Reused=true if it is taken from Idle connection pool
	//                 - need to remember trace of idle connections (even after ClearTrace) - removed by Close()
	//           - to test it: https://golang.cafe/blog/how-to-reuse-http-connections-in-go.html;
	//                         https://stackoverflow.com/questions/57683132/turning-off-connection-pool-for-go-http-client
	//        - (optional) socket trace (of upper-layer data - above TLS):
	//           - total send + received L4 payload bytes (part of socket trace, see below)
	//           - read ops - array of:
	//              recv begin+end time, len, error(-s unwrapped?)
	//           - write ops - array of
	//              write begin+end time, len, error(-s unwrapped?)
	//      - TLS trace - there could be also TLS inside for proxy (multiple TLSes for one TCP conn)
	//           - ref. tcp connection ID
	//           - handshake start time, handshake done time, error(-s unwrapped?)
	//           - for every (known) peer cert in the chain: subject, issuer, validity time range (NotBefore, NotAfter)
	//              - if validation fail, this can be obtained from the error
	//           - negotiated proto (ALPN), Server Name (SNI), negotiated CipherSuite (https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-4)
	//      - (optional) HTTP trace - array of request+response pair:
	//        - request: ref. TCP conn ID,
	//                   time when it was sent,
	//                   method, URI, HTTP version, headers (all, or only some? - what about sensitive info?),
	//                   message content length (not transport length which can differ),
	//        - response: ref. TCP conn ID,
	//                    time when it was received (first byte, fully), error (unwrapped?)
	//                    (stuff below can be undefined)
	//                    status code, HTTP version, headers (all, or only some? - what about sensitive info?),
	//                    message content length (not transport length which can differ),
	//
	//   - Use dial & tcp IDs (or some kind of IDs to reference between events within HTTP trace)
	//        - only unique within a trace
	//        - can be dial0, dial1, ..., tcpconn0, tcpconn1, ...
	//   - print to logs as JSON formatted - easier to pretty print
	//   - TODO: see how hard is it to get using BPF:
	//        - ack dup count (problems in server->client dir) + retransmission count (problems in client->server dir)
	//        - last recv ack + sack (i.e. where it got stuck on the client->server direction)
	//        - last sent ack + sack (i.e. where it got stuck on the server->client direction)
	//        - see: https://blog.devgenius.io/how-to-write-ebpf-programs-with-golang-933d58fc5dba
	//        - see: https://manpages.ubuntu.com/manpages/bionic/man8/tcpretrans-perf.8.html
	//   - TODO: test upgrade from HTTP 1.x to HTTP 2 (response code 101)
	//            - should be OK if supported by Golang's HTTP client
}
