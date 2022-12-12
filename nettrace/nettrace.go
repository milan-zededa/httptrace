package nettrace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// NetTrace : recording of network operations performed by a client program
// (e.g. HTTP client).
type NetTrace struct {
	// Description provided by the caller when tracing is initiated.
	Description string `json:"description"`
	// TraceBeginAt : (absolute) timestamp of the moment when the tracing started.
	TraceBeginAt Timestamp `json:"traceBeginAt"`
	// TraceEndAt : time (relative to TraceBeginAt) when the tracing ended.
	TraceEndAt Timestamp `json:"traceEndAt"`
	// Dials : all atempts to establish connection with a remote endpoint.
	Dials DialTraces `json:"dials"`
	// TCPConns : all established or failed TCP connections.
	TCPConns TCPConnTraces `json:"tcpConns"`
	// UDPConns : all UDP connections (successful or failed exchanges of UDP datagrams).
	UDPConns UDPConnTraces `json:"udpConns"`
	// DNSQueries : all performed DNS queries.
	// Empty if WithDNSQueryTrace is not enabled.
	DNSQueries DNSQueryTraces `json:"dnsQueries"`
	// TLSTunnels : all opened (or attempted to open) TLS tunnels.
	TLSTunnels TLSTunnelTraces `json:"tlsTunnels"`
}

// HTTPTrace : recording of network operations performed by an HTTP client.
type HTTPTrace struct {
	NetTrace
	// HTTPRequests : all executed HTTP requests.
	HTTPRequests HTTPReqTraces `json:"httpRequests"`
}

// DialTrace : recording of an attempt to establish TCP connection with a remote endpoint.
// The endpoint can be addressed using an IP address or a domain name.
type DialTrace struct {
	// TraceID : trace identifier for reference.
	TraceID TraceID `json:"traceID"`
	// DialBeginAt : time when the dial attempt started.
	DialBeginAt Timestamp `json:"dialBeginAt"`
	// DialEndAt : time when the dial attempt ended - either successfully with an established
	// connection or when it failed and gave up.
	DialEndAt Timestamp `json:"dialEndAt"`
	// CtxCloseAt : time when the context assigned to the dial attempt was closed/canceled
	// by the caller.
	CtxCloseAt Timestamp `json:"ctxCloseAt"`
	// DstAddress : address of the remote endpoint - either IP address or a domain name.
	DstAddress string `json:"dstAddress"`
	// NetworkProxy : address of a network proxy in the format scheme://host:port
	// Empty string if the connections attempt was not (explicitly) proxied.
	NetworkProxy string `json:"networkProxy,omitempty"`
	// SourceIP : source IP address statically configured for the dial request.
	// Empty if the source IP was not selected statically.
	SourceIP string `json:"sourceIP,omitempty"`
	// EstablishedConn : reference to an established TCP connection.
	EstablishedConn TraceID `json:"establishedConn,omitempty"`
}

// DialTraces is a list of Dial traces.
type DialTraces []DialTrace

// Get pointer to the Dial trace with the given ID.
func (traces DialTraces) Get(id TraceID) *DialTrace {
	for i := range traces {
		if traces[i].TraceID == id {
			return &traces[i]
		}
	}
	return nil
}

// TCPConnTrace : recording of an established or even just attempted but not completed
// TCP connection.
type TCPConnTrace struct {
	// TraceID : trace identifier for reference.
	TraceID TraceID `json:"traceID"`
	// FromDial : Reference to Dial where this originated from.
	FromDial TraceID `json:"fromDial"`
	// HandshakeBeginAt : time when the TCP handshake process started (SYN packet was sent).
	HandshakeBeginAt Timestamp `json:"handshakeBeginAt"`
	// HandshakeEndAt : time when the handshake process ended - either successfully with
	// an established TCP connection or with a failure (canceled, timeouted, refused, ...).
	HandshakeEndAt Timestamp `json:"handshakeEndAt"`
	// HandshakeErr : if handshake failed to establish, here is the reason.
	HandshakeErr string `json:"handshakeErr,omitempty"`
	// ConnCloseAt : time when the connection was closed (from our side).
	ConnCloseAt Timestamp `json:"connCloseAt"`
	// AddrTuple : 4-tuple with source + destination addresses identifying the TCP connection.
	AddrTuple AddrTuple `json:"addrTuple"`
	// Reused : was this TCP connection reused between separately recorded NetTrace record?
	// For example, if two HTTP requests are separately traced (producing two NetTrace instances),
	// the first one will have recording of a new TCP connection, while the second one will
	// repeat the same TCPConnTrace, with some updates for the second request and Reused=true.
	// Note that if TCP connection is reused between traces, the Dial from each it has originated
	// (FromDial) will als reappear in the next trace.
	Reused bool `json:"reused"`
	// TotalSentBytes : total number of bytes sent as a TCP payload through this connection.
	// (i.e. TCP header and lower-layer headers are not included)
	TotalSentBytes uint16 `json:"totalSentBytes"`
	// TotalRecvBytes : total number of bytes received as a TCP payload through this connection.
	// (i.e. TCP header and lower-layer headers are not included)
	TotalRecvBytes uint16 `json:"totalRecvBytes"`
	// Conntract : conntrack entry (provided by Netfilter connection tracking system) corresponding
	// to this connection.
	// Nil if not available or if conntrack tracing was disabled.
	// Conntrack entry is taken as late as possible, i.e. preferably after the connection closes
	// but before the conntrack entry timeouts and is removed. This is to ensure that packet/byte
	// counters and conntrack/TCP states cover the entirety of the connection.
	Conntract *ConntractEntry `json:"conntrack,omitempty"`
	// SocketTrace : recording of socket operations (read, write).
	// Nil if socket tracing was not enabled.
	SocketTrace *SocketTrace `json:"socketTrace,omitempty"`
}

// TCPConnTraces is a list of TCP connection traces.
type TCPConnTraces []TCPConnTrace

// Get pointer to the TCP connection trace with the given ID.
func (traces TCPConnTraces) Get(id TraceID) *TCPConnTrace {
	for i := range traces {
		if traces[i].TraceID == id {
			return &traces[i]
		}
	}
	return nil
}

// UDPConnTrace : recording of a UDP connection (unreliable exchange of UDP datagrams between
// our UDP client and a remote UDP peer).
type UDPConnTrace struct {
	// TraceID : trace identifier for reference.
	TraceID TraceID `json:"traceID"`
	// FromDial : Reference to Dial where this originated from.
	FromDial TraceID `json:"fromDial"`
	// SocketCreateAt : time when the UDP socket was created.
	SocketCreateAt Timestamp `json:"socketCreateAt"`
	// SocketCreateErr : if socket failed to create, here is the reason.
	SocketCreateErr string `json:"socketCreateErr,omitempty"`
	// ConnCloseAt : time when the connection was closed (from our side).
	ConnCloseAt Timestamp `json:"connCloseAt"`
	// AddrTuple : 4-tuple with source + destination addresses identifying the UDP connection.
	AddrTuple AddrTuple `json:"addrTuple"`
	// TotalSentBytes : total number of bytes sent as a UDP payload through this connection.
	// (i.e. UDP header and lower-layer headers are not included)
	TotalSentBytes uint16 `json:"totalSentBytes"`
	// TotalRecvBytes : total number of bytes received as a UDP payload through this connection.
	// (i.e. UDP header and lower-layer headers are not included)
	TotalRecvBytes uint16 `json:"totalRecvBytes"`
	// Conntract : conntrack entry (provided by Netfilter connection tracking system) corresponding
	// to this connection.
	// Nil if not available or if conntrack tracing was disabled.
	// Conntrack entry is taken as late as possible, i.e. preferably after the connection closes
	// but before the conntrack entry timeouts and is removed. This is to ensure that packet/byte
	// counters and conntrack/UDP states cover the entirety of the connection.
	Conntract *ConntractEntry `json:"conntrack,omitempty"`
	// SocketTrace : recording of socket operations (read, write).
	// Nil if socket tracing was not enabled.
	SocketTrace *SocketTrace `json:"socketTrace,omitempty"`
}

// UDPConnTraces is a list of UDP connection traces.
type UDPConnTraces []UDPConnTrace

// Get pointer to the UDP connection trace with the given ID.
func (traces UDPConnTraces) Get(id TraceID) *UDPConnTrace {
	for i := range traces {
		if traces[i].TraceID == id {
			return &traces[i]
		}
	}
	return nil
}

// DNSQueryTrace : recording of a DNS query.
type DNSQueryTrace struct {
	// TraceID : trace identifier for reference.
	TraceID TraceID `json:"traceID"`
	// FromDial : Reference to Dial where this originated from.
	FromDial TraceID `json:"fromDial"`
	// Connection : Reference to the trace record of the underlying UDP or TCP connection,
	// which was used to carry DNS request(s)/response(s).
	Connection TraceID `json:"connection"`
	// DNSQueryErr : If DNS query failed, here is the reason.
	DNSQueryErr string `json:"dnsQueryErr,omitempty"`
	// DNSQueryMsgs : all DNS query messages sent within this connection.
	DNSQueryMsgs []DNSQueryMsg `json:"dnsQueryMsgs"`
	// DNSReplyMsgs : all DNS reply messages received within this connection.
	DNSReplyMsgs []DNSReplyMsg `json:"dnsReplyMsgs"`
}

// DNSQueryTraces is a list of DNS query traces.
type DNSQueryTraces []DNSQueryTrace

// Get pointer to the DNS query trace with the given ID.
func (traces DNSQueryTraces) Get(id TraceID) *DNSQueryTrace {
	for i := range traces {
		if traces[i].TraceID == id {
			return &traces[i]
		}
	}
	return nil
}

// DNSQueryMsg : a single DNS query message.
type DNSQueryMsg struct {
	// SentAt : time when the message was sent (wrote into the socket).
	SentAt Timestamp `json:"sentAt"`
	// ID : identifier used to match DNS query with DNS reply.
	ID uint16 `json:"id"`
	// RecursionDesired : indicates if the client means a recursive query.
	RecursionDesired bool `json:"recursionDesired"`
	// Truncated : indicates that this message was truncated due to excessive length.
	Truncated bool `json:"truncated"`
	// Questions : DNS questions.
	Questions []DNSQuestion `json:"questions"`
}

// DNSQuestion : single question from DNS query message.
type DNSQuestion struct {
	// Name of the requested resource.
	Name string `json:"name"`
	// Type of RR (A, AAAA, MX, TXT, etc.)
	Type DNSResType `json:"type"`
	// Class code.
	Class uint16 `json:"class"`
}

// DNSReplyMsg : a single DNS reply message.
type DNSReplyMsg struct {
	// RecvAt : time when the message was received (read from the socket).
	RecvAt Timestamp `json:"recvAt"`
	// ID : identifier used to match DNS query with DNS reply.
	ID uint16 `json:"id"`
	// Authoritative : indicates if the DNS server is authoritative for the queried hostname.
	Authoritative bool `json:"authoritative"`
	// RecursionAvailable : indicates if the replying DNS server supports recursion.
	RecursionAvailable bool `json:"recursionAvailable"`
	// Truncated : indicates that this message was truncated due to excessive length.
	Truncated bool `json:"truncated"`
	// RCode : Response code.
	RCode DNSRCode `json:"rCode"`
	// Answers : DNS answers.
	Answers []DNSAnswer `json:"answers"`
}

// DNSAnswer : single answer from DNS reply message.
type DNSAnswer struct {
	// Name of the resource to which this record pertains.
	Name string `json:"name"`
	// Type of RR (A, AAAA, MX, TXT, etc.)
	Type DNSResType `json:"type"`
	// Class is the class of network to which this DNS resource record pertains.
	Class uint16 `json:"class"`
	// TTL is the length of time (measured in seconds) which this resource
	// record is valid for (time to live).
	TTL uint32 `json:"ttl"`
	// ResolvedVal content depends on the resource type. It can be an IP address
	// (A/AAAA), CNAME, NS, PTR, or MX (for others we do not include type-specific
	// answer attributes).
	ResolvedVal string `json:"resolvedVal,omitempty"`
}

// TLSTunnelTrace : recording of a TLS tunnel establishment
// (successful or a failed attempt).
type TLSTunnelTrace struct {
	// TraceID : trace identifier for reference.
	TraceID TraceID `json:"traceID"`
	// TCPConn : reference to TCP connection over which the tunnel was established
	// (or attempted to be established).
	TCPConn TraceID `json:"tcpConn"`
	// HandshakeBeginAt : time when the TLS handshake process started (ClientHello was sent).
	HandshakeBeginAt Timestamp `json:"handshakeBeginAt"`
	// HandshakeEndAt : time when the handshake process ended - either successfully with
	// an established TLS tunnel or with a failure (canceled, timeouted, refused, ...).
	HandshakeEndAt Timestamp `json:"handshakeEndAt"`
	// HandshakeErr : if handshake failed to establish, here is the reason.
	HandshakeErr string `json:"handshakeErr,omitempty"`
	// DidResume is true if this connection was successfully resumed from a
	// previous session with a session ticket or similar mechanism.
	DidResume bool `json:"didResume"`
	// PeerCerts are the certificates sent by the peer, in the order in which they were sent.
	// (When TLS handshake succeeds) The first element is the leaf certificate that
	// the connection is verified against.
	// However, when TLS handshake fails it might not be possible to obtain all certificates
	// and typically only one will be included (e.g. the problematic one).
	PeerCerts []PeerCert `json:"peerCerts"`
	// CipherSuite is the cipher suite negotiated for the connection (e.g.
	// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_AES_128_GCM_SHA256).
	// See: https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-4
	CipherSuite uint16 `json:"cipherSuite"`
	// NegotiatedProtocol is the application protocol negotiated with ALPN.
	// (e.g. HTTP/1.1, h2)
	NegotiatedProto string `json:"negotiatedProto"`
	// ServerName is the value of the Server Name Indication (SNI) extension sent by
	// the client. It's available both on the server and on the client side.
	ServerName string `json:"serverName"`
}

// TLSTunnelTraces is a list of TLS tunnel traces.
type TLSTunnelTraces []TLSTunnelTrace

// Get pointer to the TLS tunnel trace with the given ID.
func (traces TLSTunnelTraces) Get(id TraceID) *TLSTunnelTrace {
	for i := range traces {
		if traces[i].TraceID == id {
			return &traces[i]
		}
	}
	return nil
}

// HTTPReqTrace : recording of an HTTP request.
type HTTPReqTrace struct {
	// TraceID : trace identifier for reference.
	TraceID TraceID `json:"traceID"`
	// TCPConn : reference to the underlying TCP connection used by the HTTP request.
	TCPConn TraceID `json:"tcpConn"`
	// ProtoMajor : major number of the HTTP protocol version used for
	// request & response.
	ProtoMajor uint8 `json:"protoMajor"`
	// ProtoMinor : minor number of the HTTP protocol version used for
	// request & response.
	ProtoMinor uint8 `json:"protoMinor"`

	// Request:

	// ReqSentAt : time when the HTTP request was sent.
	ReqSentAt Timestamp `json:"reqSentAt"`
	// ReqMethod specifies the HTTP method of the request (GET, POST, PUT, etc.).
	// List of all standardized methods: https://www.iana.org/assignments/http-methods/http-methods.xhtml
	ReqMethod string `json:"reqMethod"`
	// ReqURL specifies the resource addressed by the request.
	ReqURL string `json:"reqURL"`
	// ReqHeaders : request header fields.
	// If tracing of HTTP headers is disabled (which it is by default), then this is
	// an empty slice.
	ReqHeaders HTTPHeaders `json:"reqHeaders,omitempty"`
	// ReqContentLen : size of the HTTP request body content.
	// This may be available even if Content-Length header field is not.
	// But note that this only counts the part of the content that was actually loaded
	// by the HTTP client (if it was interrupted or the content transport failed and
	// the client gave up, this would not count the whole message body).
	// This is before transfer encoding is applied on the message body.
	ReqContentLen uint64 `json:"reqContentLen"`
	// ReqError : if the HTTP request failed, this is the reason.
	ReqError string `json:"reqError,omitempty"`

	// Response:

	// RespRecvAt : time when the HTTP response was received.
	RespRecvAt Timestamp `json:"respRecvAt"`
	// RespRecvAt : response status code.
	RespStatusCode int `json:"respStatusCode"`
	// RespHeaders : response header fields.
	// If tracing of HTTP headers is disabled (which it is by default), then this is
	// an empty slice.
	RespHeaders HTTPHeaders `json:"respHeaders,omitempty"`
	// RespContentLen : number of bytes of the HTTP response body received and read
	// by the caller. This may be available even if Content-Length header field is not.
	// But note that if the caller didn't read all bytes until EOF and didn't close
	// the response body, this will not count the whole message body.
	// This is after the received content is decoded (HTTP transfer encoding).
	RespContentLen uint64 `json:"RespContentLen"`
}

// HTTPReqTraces is a list of HTTP request traces.
type HTTPReqTraces []HTTPReqTrace

// Get pointer to the HTTP request trace with the given ID.
func (traces HTTPReqTraces) Get(id TraceID) *HTTPReqTrace {
	for i := range traces {
		if traces[i].TraceID == id {
			return &traces[i]
		}
	}
	return nil
}

// HTTPHeader : a single HTTP message header field.
type HTTPHeader struct {
	// FieldName : Field name.
	FieldName string `json:"fieldName"`
	// FieldVal : Field value.
	// This can be hidden (returned as empty string even if the actual value is not empty)
	// by tracing options (can contain sensitive data).
	FieldVal string `json:"fieldVal,omitempty"`
	// FieldValLen : Length of the (actual, possibly hidden) field value (in characters).
	// Just like field value, this can be also hidden (returned as zero) using tracing
	// options (e.g. if knowing value length is enough to raise security concern).
	FieldValLen uint32 `json:"fieldValLen"`
}

// HTTPHeaders is a list of HTTP headers.
type HTTPHeaders []HTTPHeader

// Get pointer to the HTTP header field with the given name.
func (headers HTTPHeaders) Get(name string) *HTTPHeader {
	// According to RFC2616, field names are case-insensitive.
	name = strings.ToLower(name)
	for i := range headers {
		if strings.ToLower(headers[i].FieldName) == name {
			return &headers[i]
		}
	}
	return nil
}

// PeerCert : description of a peer certificate.
type PeerCert struct {
	// Subject describes the certificate subject (roughly following
	// the RFC 2253 Distinguished Names syntax).
	Subject string `json:"subject"`
	// Issuer describes the certificate issuer (roughly following
	// the RFC 2253 Distinguished Names syntax).
	Issuer string `json:"issuer"`
	// NotBefore : date and time on which the certificate becomes valid.
	NotBefore Timestamp `json:"notBefore"`
	// NotAfter : date and time after which the certificate is no longer valid.
	NotAfter Timestamp `json:"notAfter"`
	// IsCA : true if this certificate corresponds to a certificate authority.
	IsCA bool `json:"isCA"`
}

// AddrTuple : source + destination addresses fully identifying a network connection.
// Whether this is from our side or a remote side, before or after NAT, depends
// on the context.
type AddrTuple struct {
	// SrcIP : source IP address.
	SrcIP string `json:"srcIP"`
	// SrcPort : source port.
	SrcPort uint16 `json:"srcPort"`
	// DstIP : destination IP address.
	DstIP string `json:"dstIP"`
	// DstPort : destination port.
	DstPort uint16 `json:"dstPort"`
}

// ConntractEntry : single conntrack entry (one tracked connection).
// L4 protocol depends on the context, i.e. whether it is under TCPConnTrace or UDPConnTrace.
type ConntractEntry struct {
	// CapturedAt : time when this conntrack entry was obtained.
	CapturedAt Timestamp `json:"capturedAt"`
	// Status : conntrack connection's status flags.
	Status ConntrackStatus `json:"status"`
	// TCPState : state of the TCP connection.
	// TCPStateNone if this is a non-TCP (UDP) conntrack.
	TCPState TCPState `json:"tcpState,omitempty"`
	// Mark assigned to the connection by conntrack (CONNMARK).
	Mark uint32 `json:"mark"`
	// AddrOrig : source+dest addresses in the direction from the origin,
	// i.e. client->server, before NAT.
	AddrOrig AddrTuple `json:"addrOrig"`
	// AddrReply : source+dest addresses in the reply direction,
	// i.e. server->client, after NAT.
	AddrReply AddrTuple `json:"addrReply"`
	// PacketsSent : number of packets sent out towards the remote endpoint.
	PacketsSent uint64 `json:"packetsSent"`
	// PacketsRecv : number of packets received from the remote endpoint.
	PacketsRecv uint64 `json:"packetsRecv"`
	// BytesSent : number of bytes sent out towards the remote endpoint.
	BytesSent uint64 `json:"bytesSent"`
	// BytesRecv : number of bytes received from the remote endpoint.
	BytesRecv uint64 `json:"bytesRecv"`
}

// SocketTrace : recording of I/O operations performed over AF_INET(6) socket.
type SocketTrace struct {
	SocketOps []SocketOp `json:"socketOps"`
}

// SocketOp : single I/O operation performed over AF_INET(6) socket.
type SocketOp struct {
	// Type of the operation.
	Type SocketOpType `json:"type"`
	// CallAt : Time when the socket operation was initiated by the caller.
	CallAt Timestamp `json:"callAt"`
	// ReturnAt : Time when the socket operation returned.
	ReturnAt Timestamp `json:"returnAt"`
	// ReturnErr : error returned by the operation (if any).
	ReturnErr string `json:"returnErr,omitempty"`
	// RemoteAddr : with packet-oriented operation (readFrom, writeTo), this field
	// will contain address of the remote endpoint from which the packet was received
	// or to which it was sent. The address is in the format host:port.
	RemoteAddr string `json:"remoteAddr,omitempty"`
	// DataLen : number of read/written bytes.
	DataLen uint32 `json:"dataLen"`
}

// TraceID : identifier for a trace record (of any type - can be DialTrace, TCPConnTrace, etc.).
// Empty string is not a valid ID and can be used as undefined reference.
type TraceID string

// Timestamp : absolute or relative timestamp for a traced event.
// Zero value (IsRel is False && Abs.IsZero() is true) represents undefined
// timestamp.
type Timestamp struct {
	// Abs : Absolute time. Used when absolute time is needed (e.g. start of tracing)
	// or when relative time is not appropriate (e.g. reused connection would have
	// negative Rel time).
	// Ignore if IsRel=true.
	Abs time.Time
	// IsRel : true if this timestamp is relative (Rel should be read instead of Abs)
	IsRel bool
	// Number of milliseconds elapsed since NetTrace.TraceBeginAt
	Rel uint32
}

// Undefined returns true when timestamp is not defined.
func (t Timestamp) Undefined() bool {
	return t.IsRel == false && t.Abs.IsZero()
}

// MarshalJSON marshals Timestamp as a quoted json string.
func (t Timestamp) MarshalJSON() ([]byte, error) {
	if t.Undefined() {
		return []byte("\"undefined\""), nil
	}
	if t.IsRel {
		return []byte(fmt.Sprintf("\"%+dms\"", t.Rel)), nil
	}
	return t.Abs.MarshalJSON()
}

// UnmarshalJSON un-marshals a quoted json string to Timestamp.
func (t *Timestamp) UnmarshalJSON(b []byte) error {
	*t = Timestamp{}
	if string(b) == "null" {
		return nil
	}
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	if len(str) == 0 || str == "undefined" {
		return nil
	}
	if str[0] == '+' || str[0] == '-' {
		// relative timestamp
		// Cut sign and unit "ms" before calling Atoi.
		if len(str) <= 3 {
			return fmt.Errorf("invalid relative timestamp: %s", str)
		}
		rel, err := strconv.Atoi(str[1 : len(str)-2])
		if err != nil {
			return err
		}
		t.IsRel = true
		t.Rel = uint32(rel)
		return nil
	}
	return t.Abs.UnmarshalJSON(b)
}

// TCPState : TCP connection states as observed by conntrack.
// See tcp_conntrack_names in netfilter/nf_conntrack_proto_tcp.c
type TCPState uint8

const (
	// TCPStateNone : TCP state is not defined/available.
	TCPStateNone TCPState = iota
	// TCPStateSynSent : SYN-only packet seen (TCP establishment 3-way handshake)
	TCPStateSynSent
	// TCPStateSynRecv : SYN-ACK packet seen (TCP establishment 3-way handshake)
	TCPStateSynRecv
	// TCPStateEstablished : ACK packet seen (TCP establishment 3-way handshake)
	TCPStateEstablished
	// TCPStateFinWait : FIN packet seen (TCP termination 4-way handshake)
	TCPStateFinWait
	// TCPStateCloseWait : ACK seen (after FIN) (TCP termination 4-way handshake)
	TCPStateCloseWait
	// TCPStateLastAck :  FIN seen (after FIN) (TCP termination 4-way handshake)
	TCPStateLastAck
	// TCPStateTimeWait : last ACK seen (TCP termination 4-way handshake)
	TCPStateTimeWait
	// TCPStateClose : closed connection (RST)
	TCPStateClose
	// TCPStateSynSent2 : SYN-only packet seen from reply dir, simultaneous open.
	TCPStateSynSent2
)

// TCPStateToString : convert TCPState to string representation
// used in JSON.
var TCPStateToString = map[TCPState]string{
	TCPStateNone:        "none",
	TCPStateSynSent:     "syn-sent",
	TCPStateSynRecv:     "sync-recv",
	TCPStateEstablished: "established",
	TCPStateFinWait:     "fin-wait",
	TCPStateCloseWait:   "close-wait",
	TCPStateLastAck:     "last-ack",
	TCPStateTimeWait:    "time-wait",
	TCPStateClose:       "close",
	TCPStateSynSent2:    "syn-sent2",
}

// TCPStateFromString : get TCPState from a string representation.
var TCPStateFromString = map[string]TCPState{
	"":            TCPStateNone,
	"none":        TCPStateNone,
	"syn-sent":    TCPStateSynSent,
	"syn-recv":    TCPStateSynRecv,
	"established": TCPStateEstablished,
	"fin-wait":    TCPStateFinWait,
	"close-wait":  TCPStateCloseWait,
	"last-ack":    TCPStateLastAck,
	"time-wait":   TCPStateTimeWait,
	"close":       TCPStateClose,
	"syn-sent2":   TCPStateSynSent2,
}

// MarshalJSON marshals the enum as a quoted json string.
func (s TCPState) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(TCPStateToString[s])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON un-marshals a quoted json string to the enum value.
func (s *TCPState) UnmarshalJSON(b []byte) error {
	var j string
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	*s = TCPStateFromString[j]
	return nil
}

// ConntrackStatus : status of a conntrack entry (combination of flags, not enum).
type ConntrackStatus uint32

// ConntrackFlags : conntrack connection's status flags, from enum ip_conntrack_status.
// uapi/linux/netfilter/nf_conntrack_common.h
var ConntrackFlags = map[string]uint32{
	// IPS_EXPECTED : it's an expected connection.
	"expected": 1,
	// IPS_SEEN_REPLY : we've seen packets both ways.
	"seen-reply": 1 << 1,
	// IPS_ASSURED : conntrack should never be early-expired.
	"assured": 1 << 2,
	// IPS_CONFIRMED : connection is confirmed, originating packet has left box.
	"confirmed": 1 << 3,
	// IPS_SRC_NAT : connection needs src NAT in orig dir.
	"src-nat": 1 << 4,
	// IPS_DST_NAT : connection needs dst NAT in orig dir.
	"dst-nat": 1 << 5,
	// IPS_SEQ_ADJUST : connection needs TCP sequence adjusted.
	"seq-adjust": 1 << 6,
	// IPS_SRC_NAT_DONE : src NAT in orig dir was performed.
	"src-nat-done": 1 << 7,
	// IPS_DST_NAT_DONE : dst NAT in orig dir was performed.
	"dst-nat-done": 1 << 8,
	// IPS_DYING : connection is dying (removed from lists).
	"dying": 1 << 9,
	// IPS_FIXED_TIMEOUT : connection has fixed timeout.
	"fixed-timeout": 1 << 10,
	// IPS_TEMPLATE : conntrack is a template.
	"template": 1 << 11,
	// IPS_UNTRACKED : conntrack is a fake untracked entry. Obsolete and not used anymore.
	"untracked": 1 << 12,
	// IPS_HELPER: conntrack got a helper explicitly attached (ruleset, ctnetlink).
	"helper": 1 << 13,
	// IPS_OFFLOAD: conntrack has been offloaded to flow table.
	"offload": 1 << 14,
}

// MarshalJSON marshals ConntrackStatus (flags) as a quoted json string.
func (s ConntrackStatus) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	firstFlag := true
	for flagStr, flagVal := range ConntrackFlags {
		if uint32(s)&flagVal > 0 {
			if !firstFlag {
				buffer.WriteString(`|`)
			}
			buffer.WriteString(flagStr)
			firstFlag = false
		}
	}
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON un-marshals a quoted json string to ConntrackStatus (flags).
func (s *ConntrackStatus) UnmarshalJSON(b []byte) error {
	var flagsStr string
	if err := json.Unmarshal(b, &flagsStr); err != nil {
		return err
	}
	flags := strings.Split(flagsStr, "|")
	var status uint32
	for _, flagStr := range flags {
		if flagVal, ok := ConntrackFlags[flagStr]; ok {
			status |= flagVal
		}
	}
	*s = ConntrackStatus(status)
	return nil
}

// SocketOpType : operations that can be performed over AF_INET(6) socket.
type SocketOpType uint8

const (
	// SocketOpTypeUnrecognized : operation is not recognized.
	SocketOpTypeUnrecognized SocketOpType = iota
	// SocketOpTypeRead : read bytes from connected socket.
	SocketOpTypeRead
	// SocketOpTypeReadFrom : read packet from connected socket.
	// (also see SocketOp.RemoteAddr)
	SocketOpTypeReadFrom
	// SocketOpTypeWrite : write bytes to connected socket.
	SocketOpTypeWrite
	// SocketOpTypeWriteTo : write packet destined to a given address
	// (see SocketOp.RemoteAddr).
	SocketOpTypeWriteTo
)

// SocketOpTypeToString : convert SocketOpType to string representation
// used in JSON.
var SocketOpTypeToString = map[SocketOpType]string{
	SocketOpTypeUnrecognized: "unrecognized-op",
	SocketOpTypeRead:         "read",
	SocketOpTypeReadFrom:     "read-from",
	SocketOpTypeWrite:        "write",
	SocketOpTypeWriteTo:      "write-to",
}

// SocketOpTypeFromString : get SocketOpType from a string representation.
var SocketOpTypeFromString = map[string]SocketOpType{
	"":                SocketOpTypeUnrecognized,
	"unrecognized-op": SocketOpTypeUnrecognized,
	"read":            SocketOpTypeRead,
	"read-from":       SocketOpTypeReadFrom,
	"write":           SocketOpTypeWrite,
	"write-to":        SocketOpTypeWriteTo,
}

// MarshalJSON marshals the enum as a quoted json string.
func (s SocketOpType) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(SocketOpTypeToString[s])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON un-marshals a quoted json string to the enum value.
func (s *SocketOpType) UnmarshalJSON(b []byte) error {
	var j string
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	*s = SocketOpTypeFromString[j]
	return nil
}

// DNSRCode : https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
type DNSRCode uint16

const (
	// DNSRCodeNoError : No error.
	DNSRCodeNoError DNSRCode = iota
	// DNSRCodeFormatErr : Format Error.
	DNSRCodeFormatErr
	// DNSRCodeServFail : Server Failure.
	DNSRCodeServFail
	// DNSRCodeNXDomain : Non-Existent Domain.
	DNSRCodeNXDomain
	// DNSRCodeNotImp : Not Implemented.
	DNSRCodeNotImp
	// DNSRCodeRefused : Query Refused.
	DNSRCodeRefused
	// DNSRCodeUnrecognized : used for every other RCode.
	// Note that other types of errors are unlikely to be encountered from a client
	// (and are not recognized by the DNS message parser that we use anyway).
	DNSRCodeUnrecognized = 65534 // not assigned by IANA
)

// DNSRCodeToString : convert DNSRCode to string representation
// used in JSON.
var DNSRCodeToString = map[DNSRCode]string{
	DNSRCodeUnrecognized: "unrecognized-rcode",
	DNSRCodeNoError:      "no-error",
	DNSRCodeFormatErr:    "format-error",
	DNSRCodeServFail:     "server-fail",
	DNSRCodeNXDomain:     "non-existent-domain",
	DNSRCodeNotImp:       "not-implemented",
	DNSRCodeRefused:      "query-refused",
}

// DNSRCodeFromString : get DNSRCode from a string representation.
var DNSRCodeFromString = map[string]DNSRCode{
	"":                    DNSRCodeUnrecognized,
	"unrecognized-rcode":  DNSRCodeUnrecognized,
	"no-error":            DNSRCodeNoError,
	"format-error":        DNSRCodeFormatErr,
	"server-fail":         DNSRCodeServFail,
	"non-existent-domain": DNSRCodeNXDomain,
	"not-implemented":     DNSRCodeNotImp,
	"query-refused":       DNSRCodeRefused,
}

// MarshalJSON marshals the enum as a quoted json string.
func (s DNSRCode) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(DNSRCodeToString[s])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON un-marshals a quoted json string to the enum value.
func (s *DNSRCode) UnmarshalJSON(b []byte) error {
	var j string
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	*s = DNSRCodeFromString[j]
	return nil
}

// DNSResType : https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
type DNSResType uint16

const (
	// DNSResTypeUnrecognized : unrecognized Resource Record (RR) type.
	// Note that RR types not listed here are unlikely to be encountered from a client
	// (and are not recognized by the DNS message parser that we use anyway).
	DNSResTypeUnrecognized DNSResType = iota // 0 is reserved

	DNSResTypeA     DNSResType = 1
	DNSResTypeNS    DNSResType = 2
	DNSResTypeCNAME DNSResType = 5
	DNSResTypeSOA   DNSResType = 6
	DNSResTypeWKS   DNSResType = 11
	DNSResTypePTR   DNSResType = 12
	DNSResTypeHINFO DNSResType = 13
	DNSResTypeMINFO DNSResType = 14
	DNSResTypeMX    DNSResType = 15
	DNSResTypeTXT   DNSResType = 16
	DNSResTypeAAAA  DNSResType = 28
	DNSResTypeSRV   DNSResType = 33
	DNSResTypeOPT   DNSResType = 41
	DNSResTypeAXFR  DNSResType = 252
	DNSResTypeALL   DNSResType = 255
)

// DNSResTypeToString : convert DNSResType to string representation
// used in JSON.
var DNSResTypeToString = map[DNSResType]string{
	DNSResTypeUnrecognized: "unrecognized-type",
	DNSResTypeA:            "A",
	DNSResTypeNS:           "NS",
	DNSResTypeCNAME:        "CNAME",
	DNSResTypeSOA:          "SOA",
	DNSResTypeWKS:          "WKS",
	DNSResTypePTR:          "PTR",
	DNSResTypeHINFO:        "HINFO",
	DNSResTypeMINFO:        "MINFO",
	DNSResTypeMX:           "MX",
	DNSResTypeTXT:          "TXT",
	DNSResTypeAAAA:         "AAAA",
	DNSResTypeSRV:          "SRV",
	DNSResTypeOPT:          "OPT",
	DNSResTypeAXFR:         "AXFR",
	DNSResTypeALL:          "ALL",
}

// DNSResTypeFromString : get DNSResType from a string representation.
var DNSResTypeFromString = map[string]DNSResType{
	"":                  DNSResTypeUnrecognized,
	"unrecognized-type": DNSResTypeUnrecognized,
	"A":                 DNSResTypeA,
	"NS":                DNSResTypeNS,
	"CNAME":             DNSResTypeCNAME,
	"SOA":               DNSResTypeSOA,
	"WKS":               DNSResTypeWKS,
	"PTR":               DNSResTypePTR,
	"HINFO":             DNSResTypeHINFO,
	"MINFO":             DNSResTypeMINFO,
	"MX":                DNSResTypeMX,
	"TXT":               DNSResTypeTXT,
	"AAAA":              DNSResTypeAAAA,
	"SRV":               DNSResTypeSRV,
	"OPT":               DNSResTypeOPT,
	"AXFR":              DNSResTypeAXFR,
	"ALL":               DNSResTypeALL,
}

// MarshalJSON marshals the enum as a quoted json string.
func (s DNSResType) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(DNSResTypeToString[s])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON un-marshals a quoted json string to the enum value.
func (s *DNSResType) UnmarshalJSON(b []byte) error {
	var j string
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	*s = DNSResTypeFromString[j]
	return nil
}
