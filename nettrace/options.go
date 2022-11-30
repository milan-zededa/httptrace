package nettrace

// TraceOpt allows to customize tracing of network events.
type TraceOpt interface {
	isTraceOpt()
}

// WithConntrack : obtain and include conntrack entries (provided by netfilter)
// inside the trace records of TCP and UDP connections (TCPConnTrace.Conntrack
// and UDPConnTrace.Conntrack).
type WithConntrack struct {
}

func (o WithConntrack) isTraceOpt() {}

// WithSockTrace : record read/write operations performed over AF_INET sockets
// of traced TCP and UDP connections (stored under TCPConnTrace.SocketTrace and
// UDPConnTrace.SocketTrace).
type WithSockTrace struct {
}

func (o WithSockTrace) isTraceOpt() {}

// WithDNSQueryTrace : enable tracing of DNS queries and their responses (requires
// to parse DNS messages sent over a socket).
// DNSQueryTrace-s are stored under NetTrace.DNSQueries.
type WithDNSQueryTrace struct {
}

func (o WithDNSQueryTrace) isTraceOpt() {}

// WithHTTPReqTrace : enable tracing of HTTP requests and their responses.
// This requires to put a custom RoundTripper implementation under
// http.Client.Transport. However, some libraries that take HTTP client
// as an argument may expect that Transport is of type http.Transport (the standard
// implementation). In such cases, it is necessary to disable HTTP request tracing.
// As an unfortunate side effect, HTTPTrace returned by HTTPClient will also miss
// TLSTunnels, which it has no way of capturing anymore.
type WithHTTPReqTrace struct {
	// HeaderFields : specify how HTTP header fields should be recorded.
	HeaderFields HdrFieldsOpt
	// ExcludeHeaderField is a callback that can be optionally specified to filter
	// out some HTTP header fields from being recorded (by returning true).
	ExcludeHeaderField func(key, value string) bool
}

// HdrFieldsOpt : options for capturing of HTTP header fields.
type HdrFieldsOpt uint8

const (
	// HdrFieldsOptDisabled : do not capture and include HTTP header fields
	// in HTTPReqTrace (may contain sensitive data).
	HdrFieldsOptDisabled HdrFieldsOpt = iota
	// HdrFieldsOptNamesOnly : record only header field names without values
	// and their length.
	// ExcludeHeaderField may still be used to completely filter out some header
	// fields.
	HdrFieldsOptNamesOnly
	// HdrFieldsOptValueLenOnly : for each header field record the name and
	// the value length, but not the value itself.
	// ExcludeHeaderField may still be used to completely filter out some header
	// fields.
	HdrFieldsOptValueLenOnly
	// HdrFieldsOptWithValues : record every header field including values.
	// ExcludeHeaderField may still be used to completely filter out some header
	// fields.
	HdrFieldsOptWithValues
)

func (o WithHTTPReqTrace) isTraceOpt() {}

// WithPacketCapture : run packet capture on selected interfaces (in both directions).
// Captured packets are typically filtered to contain only those that correspond
// to traced connections.
// Packet capture is returned as PacketCapture - one per each interface.
type WithPacketCapture struct {
	// Interfaces to capture packets from.
	Interfaces []string
	// PacketSnaplen : maximum size in bytes to read for each packet.
	// Larger packets will be (silently) returned truncated.
	PacketSnaplen uint32
	// TotalSizeLimit : total limit in bytes for all captured packets.
	// Once the limit is reached, further captured packets are dropped or the pcap process
	// is completely stopped/paused. To indicate that this happened, the returned
	// PacketCapture will have .Truncated set to true.
	TotalSizeLimit uint32
}

func (o WithPacketCapture) isTraceOpt() {}
