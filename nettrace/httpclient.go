package nettrace

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// HTTPClient wraps and enhances the standard HTTP client with tracing
// capabilities, i.e. monitoring and recording of network events related to the operations
// of the HTTP client, including HTTP requests made, TCP connections opened/attempted,
// TLS tunnels established/attempted, DNS queries sent, DNS answers received, etc.
type HTTPClient struct {
	// The standard HTTP client is embedded and can be accessed simply as .Client
	// DO NOT change the Client.Transport field (to customize the HTTP client
	// behaviour), otherwise tracing functionality may get broken. Instead, configure
	// the desired behaviour of the HTTP client inside the HTTPClientCfg argument
	// of the HTTPClient constructor.
	*http.Client
}

// HTTPClientCfg : configuration for the embedded HTTP client.
// This is not related to tracing but how the standard HTTP client itself should behave.
// Normally, HTTP client is configured by customizing the client's Transport
// (see https://pkg.go.dev/net/http#Transport).
// However, for the HTTP client tracing to function properly, Client.Transport,
// as installed and customized by the NewHTTPClient() constructor, should not be modified.
// The only allowed action is to additionally wrap the Transport with a RoundTripper
// implementation, which is allowed to for example modify HTTP requests/responses,
// but still should call the wrapped Transport for the HTTP request execution.
// An example of this is Transport from the oauth2 package, adding an Authorization
// header with a token: https://pkg.go.dev/golang.org/x/oauth2#Transport
type HTTPClientCfg struct {
	// PreferHTTP2, if true, will make the HTTP client to chose HTTP/2 as the preferred
	// HTTP version during the Application-Layer Protocol Negotiation (ALPN).
	PreferHTTP2 bool
	// SourceIP : source IP address to use for all connections and packets sent.
	// This includes all TCP connections opened for HTTP requests and UDP
	// packets sent with DNS requests.
	// Leave as nil to not bind sockets to any source IP address and instead let
	// the kernel to select the source IP address for each connection based on
	// the routing decision.
	SourceIP net.IP
	// SkipNameserver can be optionally provided as a callback to exclude some
	// of the system-wide configured DNS server(s) that would be otherwise used
	// for DNS queries.
	// The callback is called for every configured DNS server just before it is
	// queried. If the callback returns true, the server is skipped and the resolver
	// moves to the next one.
	// When all available DNS servers are skipped, DNS query will fail and error
	// AllNameserversSkipped will be recorded in the trace under DNSQueryTrace.DNSQueryErr
	SkipNameserver func(ipAddr net.IP, port uint16) bool
	// Proxy specifies a callback to return an address of a network proxy that
	// should be used for an HTTP request targeted at the given URL.
	// If Proxy is nil or returns a nil *URL, no proxy is used.
	Proxy func(reqURL *url.URL) (*url.URL, error)
	// TLSClientConfig specifies the TLS configuration to use for TLS tunnels.
	// If nil, the default configuration is used.
	TLSClientConfig *tls.Config
	// ReqTimeout specifies a time limit for requests made by the HTTP client.
	// The timeout includes connection time, any redirects, and reading the response body.
	// The timer remains running after Get, Head, Post, or Do return and will interrupt
	// reading of the Response.Body.
	ReqTimeout time.Duration
	// TLSHandshakeTimeout specifies the maximum amount of time waiting to
	// wait for a TLS handshake. Zero means no timeout.
	TLSHandshakeTimeout time.Duration
	// DisableKeepAlives, if true, disables HTTP keep-alives and will only use the connection
	// to the server for a single HTTP request.
	DisableKeepAlives bool
	// DisableCompression, if true, prevents the Transport from requesting compression with
	// an "Accept-Encoding: gzip" request header when the Request contains no existing
	// Accept-Encoding value.
	DisableCompression bool
	// MaxIdleConns controls the maximum number of idle (keep-alive) connections across
	// all hosts. Zero means no limit.
	MaxIdleConns int
	// MaxIdleConnsPerHost, if non-zero, controls the maximum idle (keep-alive) connections
	// to keep per-host. If zero, DefaultMaxIdleConnsPerHost from the http package is used.
	MaxIdleConnsPerHost int
	// MaxConnsPerHost optionally limits the total number of connections per host,
	// including connections in the dialing, active, and idle states. On limit violation,
	// dials will block.
	// Zero means no limit.
	MaxConnsPerHost int
	// IdleConnTimeout is the maximum amount of time an idle (keep-alive) connection will
	// remain idle before closing itself.
	// Zero means no limit.
	IdleConnTimeout time.Duration
	// ResponseHeaderTimeout, if non-zero, specifies the amount of time to wait for a server's
	// response headers after fully writing the request (including its body, if any).
	// This time does not include the time to read the response body.
	ResponseHeaderTimeout time.Duration
}

// AllNameserversSkipped is returned in DNSQueryTrace.DNSQueryErr when all configured
// DNS servers are skipped as decided by the HTTPClientCfg.SkipNameserver callback.
// Note that there must be at least one skipped nameserver - if the system has no DNS
// server configured, a different error is returned (from the standard net package).
type AllNameserversSkipped struct {
	Nameservers []string // [ip:port]
}

// Error message.
func (e *AllNameserversSkipped) Error() string {
	return fmt.Sprintf("all DNS servers were skipped: %v", e.Nameservers)
}

// Logger is used to log noteworthy tracing-related events happening inside HTTPClient.
type Logger interface {
	// Tracef : formatted log message with info useful for finer-grained debugging.
	Tracef(format string, args ...interface{})
	// Noticef : formatted log message with info useful for debugging.
	Noticef(format string, args ...interface{})
	// Warningf : formatted log message with a warning.
	Warningf(format string, args ...interface{})
	// Errorf : formatted log message with an error.
	Errorf(format string, args ...interface{})
	// Fatalf : formatted log message with an error, ending with a call to os.Exit()
	// with non-zero return value.
	Fatalf(format string, args ...interface{})
	// Panicf : formatted log message with an error, raising a panic.
	Panicf(format string, args ...interface{})
}

// NewHTTPClient creates a new instance of HTTPClient, enhancing the standard
// http.Client with tracing capabilities.
// Tracing starts immediately:
//   - a background Go routine collecting traces is started
//   - packet capture starts on selected interfaces if WithPacketCapture option was passed
func NewHTTPClient(config HTTPClientCfg, log Logger, traceOpts ...TraceOpt) *HTTPClient {
	return &HTTPClient{
		Client: &http.Client{
			Transport: nil, // TODO
			Timeout:   config.ReqTimeout,
		},
	}
}

// GetTrace returns a summary of all network and HTTP trace records (aka HTTPTrace),
// collected since the tracing last (re)started (either when the client was created
// or when the last ClearTrace() was called).
// This will include packet capture for every selected interface if it was enabled.
// The method allows to insert some description into the returned HTTPTrace
// (e.g. “download image XYZ”).
// Note that .TraceEndAt of the returned HTTPTrace is set to the current time.
// Also note that this does not stop tracing or clears the collected traces - use Close()
// or ClearTrace() for that.
func (t *HTTPClient) GetTrace(description string) (HTTPTrace, []PacketCapture, error) {
	// TODO
	return HTTPTrace{NetTrace: NetTrace{Description: description}}, nil, nil
}

// ClearTrace effectively restarts tracing by removing all traces collected up to
// this point. If packet capture is enabled (WithPacketCapture), packets captured
// so far are deleted.
// However, note that if TCP connection is reused from a previous run, it will reappear
// in the HTTPTrace (returned by GetTrace()) with some attributes restored to their previously
// recorded values (like .HandshakeBeginAt) and some updated (for example .Reused will be set
// to true).
func (t *HTTPClient) ClearTrace() error {
	// TODO
	return nil
}

// Close stops tracing of the embedded HTTP client, including packet capture if it
// was enabled.
// After this, it would be invalid to call GetTrace(), ClearTrace() or even to keep using
// the embedded HTTP Client.
func (t *HTTPClient) Close() error {
	// TODO
	return nil
}
