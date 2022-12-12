package nettrace_test

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"example.com/httptrace/nettrace"
	. "github.com/onsi/gomega"
)

func relTimeIsInBetween(t *WithT, timestamp, lowerBound, upperBound nettrace.Timestamp) {
	t.Expect(timestamp.IsRel).To(BeTrue())
	t.Expect(lowerBound.IsRel).To(BeTrue())
	t.Expect(upperBound.IsRel).To(BeTrue())
	t.Expect(timestamp.Rel >= lowerBound.Rel).To(BeTrue())
	t.Expect(timestamp.Rel <= upperBound.Rel).To(BeTrue())
}

func TestHTTPTracing(test *testing.T) {
	startTime := time.Now()
	t := NewWithT(test)

	// Options that do not require administrative privileges.
	opts := []nettrace.TraceOpt{
		nettrace.WithLogging{},
		nettrace.WithHTTPReqTrace{
			HeaderFields: nettrace.HdrFieldsOptWithValues,
		},
		nettrace.WithSockTrace{},
		nettrace.WithDNSQueryTrace{},
	}
	client, err := nettrace.NewHTTPClient(nettrace.HTTPClientCfg{
		PreferHTTP2: true,
		ReqTimeout:  5 * time.Second,
	}, opts...)
	t.Expect(err).ToNot(HaveOccurred())

	req, err := http.NewRequest("GET", "https://www.example.com", nil)
	resp, err := client.Do(req)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(resp).ToNot(BeNil())
	t.Expect(resp.StatusCode).To(Equal(200))
	t.Expect(resp.Body).ToNot(BeNil())
	body := new(strings.Builder)
	_, err = io.Copy(body, resp.Body)
	t.Expect(err).ToNot(HaveOccurred())
	err = resp.Body.Close()
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(body.String()).To(ContainSubstring("<html>"))
	t.Expect(body.String()).To(ContainSubstring("</html>"))

	trace, pcap, err := client.GetTrace("GET www.example.com over HTTPS")
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(pcap).To(BeEmpty())

	t.Expect(trace.Description).To(Equal("GET www.example.com over HTTPS"))
	t.Expect(trace.TraceBeginAt.IsRel).To(BeFalse())
	t.Expect(trace.TraceBeginAt.Abs.After(startTime)).To(BeTrue())
	t.Expect(trace.TraceBeginAt.Abs.Before(time.Now())).To(BeTrue())
	traceBeginAsRel := nettrace.Timestamp{IsRel: true, Rel: 0}
	t.Expect(trace.TraceEndAt.IsRel).To(BeTrue())
	t.Expect(trace.TraceEndAt.Rel > 0).To(BeTrue())

	// Dial trace
	t.Expect(trace.Dials).To(HaveLen(1)) // no redirects
	dial := trace.Dials[0]
	t.Expect(dial.TraceID).ToNot(BeEmpty())
	relTimeIsInBetween(t, dial.DialBeginAt, traceBeginAsRel, trace.TraceEndAt)
	relTimeIsInBetween(t, dial.DialEndAt, dial.DialBeginAt, trace.TraceEndAt)
	t.Expect(dial.NetworkProxy).To(BeEmpty())
	t.Expect(dial.SourceIP).To(BeEmpty())
	t.Expect(dial.DstAddress).To(Equal("www.example.com"))
	t.Expect(dial.EstablishedConn).ToNot(BeEmpty())
	t.Expect(trace.TCPConns.Get(dial.EstablishedConn)).ToNot(BeNil())

	// DNS trace
	t.Expect(trace.DNSQueries).To(Or(HaveLen(1), HaveLen(2))) // A and possibly also AAAA
	for _, dnsQuery := range trace.DNSQueries {
		t.Expect(dnsQuery.FromDial == dial.TraceID).To(BeTrue())
		t.Expect(dnsQuery.TraceID).ToNot(BeEmpty())
		t.Expect(dnsQuery.DNSQueryErr).To(BeEmpty())
		udpConn := trace.UDPConns.Get(dnsQuery.Connection)
		t.Expect(udpConn).ToNot(BeNil())

		t.Expect(dnsQuery.DNSQueryMsgs).To(HaveLen(1))
		dnsMsg := dnsQuery.DNSQueryMsgs[0]
		relTimeIsInBetween(t, dnsMsg.SentAt, udpConn.SocketCreateAt, udpConn.ConnCloseAt)
		t.Expect(dnsMsg.Questions).To(HaveLen(1))
		t.Expect(dnsMsg.Questions[0].Name).To(Equal("www.example.com"))
		t.Expect(dnsMsg.Questions[0].Type).To(Or(
			Equal(nettrace.DNSResTypeA), Equal(nettrace.DNSResTypeAAAA)))
		t.Expect(dnsMsg.Truncated).To(BeFalse())

		t.Expect(dnsQuery.DNSReplyMsgs).To(HaveLen(1))
		dnsReply := dnsQuery.DNSReplyMsgs[0]
		relTimeIsInBetween(t, dnsReply.RecvAt, dnsMsg.SentAt, udpConn.ConnCloseAt)
		t.Expect(dnsReply.ID == dnsMsg.ID).To(BeTrue())
		t.Expect(dnsReply.RCode).To(Equal(nettrace.DNSRCodeNoError))
		t.Expect(dnsReply.Answers).ToNot(BeEmpty())
		t.Expect(dnsReply.Truncated).To(BeFalse())
	}

	// UDP connection trace
	t.Expect(trace.UDPConns).To(Or(HaveLen(1), HaveLen(2))) // DNS for A and possibly also AAAA
	for _, udpConn := range trace.UDPConns {
		t.Expect(udpConn.TraceID).ToNot(BeEmpty())
		t.Expect(udpConn.FromDial == dial.TraceID).To(BeTrue())
		relTimeIsInBetween(t, udpConn.SocketCreateAt, dial.DialBeginAt, dial.DialEndAt)
		relTimeIsInBetween(t, udpConn.ConnCloseAt, udpConn.SocketCreateAt, dial.DialEndAt)
		t.Expect(net.ParseIP(udpConn.AddrTuple.SrcIP)).ToNot(BeNil())
		t.Expect(net.ParseIP(udpConn.AddrTuple.DstIP)).ToNot(BeNil())
		t.Expect(udpConn.AddrTuple.SrcPort).ToNot(BeZero())
		t.Expect(udpConn.AddrTuple.DstPort).ToNot(BeZero())
		t.Expect(udpConn.SocketTrace).ToNot(BeNil())
		t.Expect(udpConn.SocketTrace.SocketOps).ToNot(BeEmpty())
		for _, socketOp := range udpConn.SocketTrace.SocketOps {
			relTimeIsInBetween(t, socketOp.CallAt, udpConn.SocketCreateAt, udpConn.ConnCloseAt)
			relTimeIsInBetween(t, socketOp.ReturnAt, socketOp.CallAt, udpConn.ConnCloseAt)
		}
		t.Expect(udpConn.Conntract).To(BeNil()) // WithConntrack requires root privileges
		t.Expect(udpConn.TotalRecvBytes).ToNot(BeZero())
		t.Expect(udpConn.TotalSentBytes).ToNot(BeZero())
	}

	// TCP connection trace
	t.Expect(trace.TCPConns).To(HaveLen(1))
	tcpConn := trace.TCPConns[0]
	t.Expect(tcpConn.TraceID).ToNot(BeEmpty())
	t.Expect(tcpConn.FromDial == dial.TraceID).To(BeTrue())
	t.Expect(tcpConn.Reused).To(BeFalse())
	relTimeIsInBetween(t, tcpConn.HandshakeBeginAt, dial.DialBeginAt, dial.DialEndAt)
	relTimeIsInBetween(t, tcpConn.HandshakeEndAt, tcpConn.HandshakeBeginAt, dial.DialEndAt)
	relTimeIsInBetween(t, tcpConn.ConnCloseAt, tcpConn.HandshakeEndAt, dial.DialEndAt)
	t.Expect(tcpConn.HandshakeErr).To(BeEmpty())
	t.Expect(net.ParseIP(tcpConn.AddrTuple.SrcIP)).ToNot(BeNil())
	t.Expect(net.ParseIP(tcpConn.AddrTuple.DstIP)).ToNot(BeNil())
	t.Expect(tcpConn.AddrTuple.SrcPort).ToNot(BeZero())
	t.Expect(tcpConn.AddrTuple.DstPort).ToNot(BeZero())
	t.Expect(tcpConn.SocketTrace).ToNot(BeNil())
	t.Expect(tcpConn.SocketTrace.SocketOps).ToNot(BeEmpty())
	for _, socketOp := range tcpConn.SocketTrace.SocketOps {
		relTimeIsInBetween(t, socketOp.CallAt, tcpConn.HandshakeEndAt, tcpConn.ConnCloseAt)
		relTimeIsInBetween(t, socketOp.ReturnAt, socketOp.CallAt, tcpConn.ConnCloseAt)
	}
	t.Expect(tcpConn.Conntract).To(BeNil()) // WithConntrack requires root privileges
	t.Expect(tcpConn.TotalRecvBytes).ToNot(BeZero())
	t.Expect(tcpConn.TotalSentBytes).ToNot(BeZero())

	// TLS tunnel trace
	t.Expect(trace.TLSTunnels).To(HaveLen(1))
	tlsTun := trace.TLSTunnels[0]
	t.Expect(tlsTun.TraceID).ToNot(BeEmpty())
	t.Expect(tlsTun.TCPConn == tcpConn.TraceID).To(BeTrue())
	t.Expect(tlsTun.DidResume).To(BeFalse())
	relTimeIsInBetween(t, tlsTun.HandshakeBeginAt, tcpConn.HandshakeEndAt, tcpConn.ConnCloseAt)
	relTimeIsInBetween(t, tlsTun.HandshakeEndAt, tlsTun.HandshakeBeginAt, tcpConn.ConnCloseAt)
	t.Expect(tlsTun.HandshakeErr).To(BeEmpty())
	t.Expect(tlsTun.ServerName).To(Equal("www.example.com"))
	t.Expect(tlsTun.NegotiatedProto).To(Equal("h2"))
	t.Expect(tlsTun.CipherSuite).ToNot(BeEmpty())
	// TODO (for every peer certificate):
	t.Expect(tlsTun.PeerCerts).To(HaveLen(3))
	peerCert := tlsTun.PeerCerts[0]
	t.Expect(peerCert.IsCA).To(BeTrue())
	t.Expect(peerCert.Subject).To(Equal("TODO"))
	t.Expect(peerCert.Issuer).To(Equal("TODO"))
	t.Expect(peerCert.NotBefore.Undefined()).To(BeFalse())
	t.Expect(peerCert.NotBefore.IsRel).To(BeFalse())
	t.Expect(peerCert.NotAfter.Undefined()).To(BeFalse())
	t.Expect(peerCert.NotAfter.IsRel).To(BeFalse())
	t.Expect(peerCert.NotBefore.Abs.Before(time.Now())).To(BeTrue())
	t.Expect(peerCert.NotAfter.Abs.After(time.Now())).To(BeTrue())

	// HTTP request trace
	t.Expect(trace.HTTPRequests).To(HaveLen(1))
	httpReq := trace.HTTPRequests[0]
	t.Expect(httpReq.TraceID).ToNot(BeEmpty())
	t.Expect(httpReq.TCPConn == tcpConn.TraceID).To(BeTrue())
	t.Expect(httpReq.ProtoMajor).To(Equal(2))
	t.Expect(httpReq.ProtoMinor).To(Equal(0))
	relTimeIsInBetween(t, httpReq.ReqSentAt, traceBeginAsRel, trace.TraceEndAt)
	t.Expect(httpReq.ReqError).To(BeEmpty())
	t.Expect(httpReq.ReqMethod).To(Equal("GET"))
	t.Expect(httpReq.ReqURL).To(Equal("https://www.example.com"))
	t.Expect(httpReq.ReqHeaders).ToNot(BeEmpty())
	host := httpReq.ReqHeaders.Get("host")
	t.Expect(host).ToNot(BeNil())
	t.Expect(host.FieldVal).To(Equal("www.example.com"))
	t.Expect(host.FieldValLen).To(BeEquivalentTo(len(host.FieldVal)))
	t.Expect(httpReq.ReqContentLen).To(BeZero())
	relTimeIsInBetween(t, httpReq.RespRecvAt, httpReq.ReqSentAt, trace.TraceEndAt)
	t.Expect(httpReq.RespStatusCode).To(Equal(200))
	t.Expect(httpReq.RespHeaders).ToNot(BeEmpty())
	contentType := httpReq.RespHeaders.Get("content-type")
	t.Expect(contentType).ToNot(BeNil())
	t.Expect(contentType.FieldVal).To(ContainSubstring("text/html"))
	t.Expect(contentType.FieldValLen).To(BeEquivalentTo(len(contentType.FieldVal)))
	t.Expect(httpReq.RespContentLen).ToNot(BeZero())

	err = client.Close()
	t.Expect(err).ToNot(HaveOccurred())
}

// TestTLSCertErrors : test that even when TLS handshake fails due to a bad certificate,
// we still get the certificate issuer and the subject in the trace.
func TestTLSCertErrors(test *testing.T) {
	t := NewGomegaWithT(test)

	// Options required for TLS tracing.
	opts := []nettrace.TraceOpt{
		nettrace.WithLogging{},
		nettrace.WithHTTPReqTrace{},
	}
	client, err := nettrace.NewHTTPClient(nettrace.HTTPClientCfg{
		PreferHTTP2: true,
		ReqTimeout:  5 * time.Second,
	}, opts...)
	t.Expect(err).ToNot(HaveOccurred())

	// Expired certificate
	req, err := http.NewRequest("GET", "https://expired.badssl.com/", nil)
	resp, err := client.Do(req)
	t.Expect(err).To(HaveOccurred())
	t.Expect(resp).To(BeNil())
	trace, _, err := client.GetTrace("expired cert")
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(trace.TLSTunnels).To(HaveLen(1))
	tlsTun := trace.TLSTunnels[0]
	t.Expect(tlsTun.HandshakeErr).ToNot(BeEmpty())
	t.Expect(tlsTun.PeerCerts).To(HaveLen(1)) // when TLS fails, we only get the problematic cert
	peerCert := tlsTun.PeerCerts[0]
	t.Expect(peerCert.IsCA).To(BeFalse())
	t.Expect(peerCert.Issuer).To(Equal("TODO"))
	t.Expect(peerCert.Subject).To(Equal("TODO"))
	t.Expect(peerCert.NotBefore.Abs.IsZero()).To(BeFalse())
	t.Expect(peerCert.NotAfter.Abs.Before(time.Now())).To(BeTrue())
	err = client.ClearTrace()
	t.Expect(err).ToNot(HaveOccurred())

	// Wrong Host
	req, err = http.NewRequest("GET", "https://wrong.host.badssl.com/", nil)
	resp, err = client.Do(req)
	t.Expect(err).To(HaveOccurred())
	t.Expect(resp).To(BeNil())
	trace, _, err = client.GetTrace("wrong host")
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(trace.TLSTunnels).To(HaveLen(1))
	tlsTun = trace.TLSTunnels[0]
	t.Expect(tlsTun.HandshakeErr).ToNot(BeEmpty())
	t.Expect(tlsTun.PeerCerts).To(HaveLen(1))
	peerCert = tlsTun.PeerCerts[0]
	t.Expect(peerCert.IsCA).To(BeFalse())
	t.Expect(peerCert.Issuer).To(Equal("TODO"))
	t.Expect(peerCert.Subject).To(Equal("TODO"))
	t.Expect(peerCert.NotBefore.Abs.Before(time.Now())).To(BeTrue())
	t.Expect(peerCert.NotAfter.Abs.After(time.Now())).To(BeTrue())
	err = client.ClearTrace()
	t.Expect(err).ToNot(HaveOccurred())

	// Untrusted root
	req, err = http.NewRequest("GET", "https://untrusted-root.badssl.com/", nil)
	resp, err = client.Do(req)
	t.Expect(err).To(HaveOccurred())
	t.Expect(resp).To(BeNil())
	trace, _, err = client.GetTrace("untrusted root")
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(trace.TLSTunnels).To(HaveLen(1))
	tlsTun = trace.TLSTunnels[0]
	t.Expect(tlsTun.HandshakeErr).ToNot(BeEmpty())
	t.Expect(tlsTun.PeerCerts).To(HaveLen(1))
	peerCert = tlsTun.PeerCerts[0]
	t.Expect(peerCert.IsCA).To(BeTrue())
	t.Expect(peerCert.Issuer).To(Equal("TODO"))
	t.Expect(peerCert.Subject).To(Equal("TODO"))
	t.Expect(peerCert.NotBefore.Abs.Before(time.Now())).To(BeTrue())
	t.Expect(peerCert.NotAfter.Abs.After(time.Now())).To(BeTrue())
	err = client.ClearTrace()
	t.Expect(err).ToNot(HaveOccurred())

	err = client.Close()
	t.Expect(err).ToNot(HaveOccurred())
}

// Trace HTTP request targeted at a non-existent host name.
func TestNonExistentHost(test *testing.T) {
	t := NewGomegaWithT(test)

	// Options that do not require administrative privileges.
	opts := []nettrace.TraceOpt{
		nettrace.WithLogging{},
		nettrace.WithHTTPReqTrace{
			HeaderFields: nettrace.HdrFieldsOptWithValues,
		},
		nettrace.WithSockTrace{},
		nettrace.WithDNSQueryTrace{},
	}
	client, err := nettrace.NewHTTPClient(nettrace.HTTPClientCfg{
		ReqTimeout: 5 * time.Second,
	}, opts...)
	t.Expect(err).ToNot(HaveOccurred())

	req, err := http.NewRequest("GET", "https://non-existent-host", nil)
	resp, err := client.Do(req)
	t.Expect(err).To(HaveOccurred())
	t.Expect(resp).To(BeNil())
	trace, _, err := client.GetTrace("non-existent host")
	t.Expect(err).ToNot(HaveOccurred())
	traceBeginAsRel := nettrace.Timestamp{IsRel: true, Rel: 0}

	// Dial trace
	t.Expect(trace.Dials).To(HaveLen(1)) // one failed Dial (DNS failed)
	dial := trace.Dials[0]
	t.Expect(dial.TraceID).ToNot(BeEmpty())
	relTimeIsInBetween(t, dial.DialBeginAt, traceBeginAsRel, trace.TraceEndAt)
	relTimeIsInBetween(t, dial.DialEndAt, dial.DialBeginAt, trace.TraceEndAt)
	t.Expect(dial.DstAddress).To(Equal("non-existent-host"))
	t.Expect(dial.EstablishedConn).To(BeEmpty())

	// DNS trace
	t.Expect(trace.DNSQueries).To(Or(HaveLen(1), HaveLen(2))) // A and possibly also AAAA
	for _, dnsQuery := range trace.DNSQueries {
		t.Expect(dnsQuery.FromDial == dial.TraceID).To(BeTrue())
		t.Expect(dnsQuery.TraceID).ToNot(BeEmpty())
		t.Expect(dnsQuery.DNSQueryErr).ToNot(BeEmpty())
		udpConn := trace.UDPConns.Get(dnsQuery.Connection)
		t.Expect(udpConn).ToNot(BeNil())

		t.Expect(dnsQuery.DNSQueryMsgs).To(HaveLen(1))
		dnsMsg := dnsQuery.DNSQueryMsgs[0]
		relTimeIsInBetween(t, dnsMsg.SentAt, udpConn.SocketCreateAt, udpConn.ConnCloseAt)
		t.Expect(dnsMsg.Questions).To(HaveLen(1))
		t.Expect(dnsMsg.Questions[0].Name).To(Equal("non-existent-host"))
		t.Expect(dnsMsg.Questions[0].Type).To(Or(
			Equal(nettrace.DNSResTypeA), Equal(nettrace.DNSResTypeAAAA)))
		t.Expect(dnsMsg.Truncated).To(BeFalse())

		t.Expect(dnsQuery.DNSReplyMsgs).To(HaveLen(1))
		dnsReply := dnsQuery.DNSReplyMsgs[0]
		relTimeIsInBetween(t, dnsReply.RecvAt, dnsMsg.SentAt, udpConn.ConnCloseAt)
		t.Expect(dnsReply.ID == dnsMsg.ID).To(BeTrue())
		t.Expect(dnsReply.RCode).To(Equal(nettrace.DNSRCodeNXDomain))
		t.Expect(dnsReply.Answers).To(BeEmpty())
		t.Expect(dnsReply.Truncated).To(BeFalse())
	}

	// UDP connection trace
	t.Expect(trace.UDPConns).To(Or(HaveLen(1), HaveLen(2))) // DNS for A and possibly also AAAA
	for _, udpConn := range trace.UDPConns {
		t.Expect(udpConn.TraceID).ToNot(BeEmpty())
		t.Expect(udpConn.FromDial == dial.TraceID).To(BeTrue())
		relTimeIsInBetween(t, udpConn.SocketCreateAt, dial.DialBeginAt, dial.DialEndAt)
		relTimeIsInBetween(t, udpConn.ConnCloseAt, udpConn.SocketCreateAt, dial.DialEndAt)
		t.Expect(net.ParseIP(udpConn.AddrTuple.SrcIP)).ToNot(BeNil())
		t.Expect(net.ParseIP(udpConn.AddrTuple.DstIP)).ToNot(BeNil())
		t.Expect(udpConn.AddrTuple.SrcPort).ToNot(BeZero())
		t.Expect(udpConn.AddrTuple.DstPort).ToNot(BeZero())
		t.Expect(udpConn.SocketTrace).ToNot(BeNil())
		t.Expect(udpConn.SocketTrace.SocketOps).ToNot(BeEmpty())
		for _, socketOp := range udpConn.SocketTrace.SocketOps {
			relTimeIsInBetween(t, socketOp.CallAt, udpConn.SocketCreateAt, udpConn.ConnCloseAt)
			relTimeIsInBetween(t, socketOp.ReturnAt, socketOp.CallAt, udpConn.ConnCloseAt)
		}
		t.Expect(udpConn.Conntract).To(BeNil()) // WithConntrack requires root privileges
		t.Expect(udpConn.TotalRecvBytes).ToNot(BeZero())
		t.Expect(udpConn.TotalSentBytes).ToNot(BeZero())
	}

	// TCP connection trace
	t.Expect(trace.TCPConns).To(BeEmpty())

	// TLS tunnel trace
	t.Expect(trace.TLSTunnels).To(BeEmpty())

	// HTTP request trace
	t.Expect(trace.HTTPRequests).To(HaveLen(1))
	httpReq := trace.HTTPRequests[0]
	t.Expect(httpReq.TraceID).ToNot(BeEmpty())
	t.Expect(httpReq.TCPConn).To(BeEmpty())
	t.Expect(httpReq.ProtoMajor).To(BeZero())
	t.Expect(httpReq.ProtoMinor).To(BeZero())
	relTimeIsInBetween(t, httpReq.ReqSentAt, traceBeginAsRel, trace.TraceEndAt)
	t.Expect(httpReq.ReqError).ToNot(BeEmpty())
	t.Expect(httpReq.ReqMethod).To(Equal("GET"))
	t.Expect(httpReq.ReqURL).To(Equal("https://non-existent-host"))
	t.Expect(httpReq.ReqHeaders).ToNot(BeEmpty())
	host := httpReq.ReqHeaders.Get("host")
	t.Expect(host).ToNot(BeNil())
	t.Expect(host.FieldVal).To(Equal("non-existent-host"))
	t.Expect(host.FieldValLen).To(BeEquivalentTo(len(host.FieldVal)))
	t.Expect(httpReq.ReqContentLen).To(BeZero())
	t.Expect(httpReq.RespRecvAt.Undefined()).To(BeTrue())
	t.Expect(httpReq.RespStatusCode).To(BeZero())
	t.Expect(httpReq.RespHeaders).To(BeEmpty())
	t.Expect(httpReq.RespContentLen).To(BeZero())

	err = client.Close()
	t.Expect(err).ToNot(HaveOccurred())
}

// Trace HTTP request targeted at a non-responsive destination (nobody is listening).
func TestUnresponsiveDest(test *testing.T) {
	t := NewGomegaWithT(test)

	// Options that do not require administrative privileges.
	opts := []nettrace.TraceOpt{
		nettrace.WithLogging{},
		nettrace.WithHTTPReqTrace{
			HeaderFields: nettrace.HdrFieldsOptWithValues,
		},
		nettrace.WithSockTrace{},
		nettrace.WithDNSQueryTrace{},
	}
	client, err := nettrace.NewHTTPClient(nettrace.HTTPClientCfg{
		ReqTimeout: 5 * time.Second,
	}, opts...)
	t.Expect(err).ToNot(HaveOccurred())

	req, err := http.NewRequest("GET", "https://198.51.100.100", nil)
	resp, err := client.Do(req)
	t.Expect(err).To(HaveOccurred())
	t.Expect(resp).To(BeNil())
	trace, _, err := client.GetTrace("unresponsive dest")
	t.Expect(err).ToNot(HaveOccurred())
	traceBeginAsRel := nettrace.Timestamp{IsRel: true, Rel: 0}

	// Dial trace
	t.Expect(trace.Dials).To(HaveLen(1)) // one failed Dial (DNS failed)
	dial := trace.Dials[0]
	t.Expect(dial.TraceID).ToNot(BeEmpty())
	relTimeIsInBetween(t, dial.DialBeginAt, traceBeginAsRel, trace.TraceEndAt)
	relTimeIsInBetween(t, dial.DialEndAt, dial.DialBeginAt, trace.TraceEndAt)
	t.Expect(dial.DstAddress).To(Equal("198.51.100.100"))
	t.Expect(dial.EstablishedConn).To(BeEmpty())

	// DNS trace
	t.Expect(trace.DNSQueries).To(BeEmpty())

	// UDP connection trace
	t.Expect(trace.UDPConns).To(BeEmpty())

	// TCP connection trace
	t.Expect(trace.TCPConns).To(HaveLen(1))
	tcpConn := trace.TCPConns[0]
	t.Expect(tcpConn.TraceID).ToNot(BeEmpty())
	t.Expect(tcpConn.FromDial == dial.TraceID).To(BeTrue())
	t.Expect(tcpConn.Reused).To(BeFalse())
	relTimeIsInBetween(t, tcpConn.HandshakeBeginAt, dial.DialBeginAt, dial.DialEndAt)
	t.Expect(tcpConn.HandshakeEndAt.Undefined()).To(BeTrue())
	relTimeIsInBetween(t, tcpConn.ConnCloseAt, tcpConn.HandshakeBeginAt, dial.DialEndAt)
	t.Expect(tcpConn.HandshakeErr).ToNot(BeEmpty())
	t.Expect(net.ParseIP(tcpConn.AddrTuple.SrcIP)).ToNot(BeNil())
	t.Expect(net.ParseIP(tcpConn.AddrTuple.DstIP)).ToNot(BeNil())
	t.Expect(tcpConn.AddrTuple.SrcPort).ToNot(BeZero()) // btw. not easy to get when TLS handshake fails
	t.Expect(tcpConn.AddrTuple.DstPort).ToNot(BeZero())
	t.Expect(tcpConn.SocketTrace).To(BeEmpty())
	t.Expect(tcpConn.Conntract).To(BeNil())
	t.Expect(tcpConn.TotalRecvBytes).To(BeZero())
	t.Expect(tcpConn.TotalSentBytes).To(BeZero())

	// TLS tunnel trace
	t.Expect(trace.TLSTunnels).To(BeEmpty())

	// HTTP request trace
	t.Expect(trace.HTTPRequests).To(HaveLen(1))
	httpReq := trace.HTTPRequests[0]
	t.Expect(httpReq.TraceID).ToNot(BeEmpty())
	t.Expect(httpReq.TCPConn).To(BeEmpty())
	t.Expect(httpReq.ProtoMajor).To(BeZero())
	t.Expect(httpReq.ProtoMinor).To(BeZero())
	relTimeIsInBetween(t, httpReq.ReqSentAt, traceBeginAsRel, trace.TraceEndAt)
	t.Expect(httpReq.ReqError).ToNot(BeEmpty())
	t.Expect(httpReq.ReqMethod).To(Equal("GET"))
	t.Expect(httpReq.ReqURL).To(Equal("https://198.51.100.100"))
	t.Expect(httpReq.ReqHeaders).ToNot(BeEmpty())
	host := httpReq.ReqHeaders.Get("host")
	t.Expect(host).ToNot(BeNil())
	t.Expect(host.FieldVal).To(Equal("198.51.100.100"))
	t.Expect(host.FieldValLen).To(BeEquivalentTo(len(host.FieldVal)))
	t.Expect(httpReq.ReqContentLen).To(BeZero())
	t.Expect(httpReq.RespRecvAt.Undefined()).To(BeTrue())
	t.Expect(httpReq.RespStatusCode).To(BeZero())
	t.Expect(httpReq.RespHeaders).To(BeEmpty())
	t.Expect(httpReq.RespContentLen).To(BeZero())

	err = client.Close()
	t.Expect(err).ToNot(HaveOccurred())
}
