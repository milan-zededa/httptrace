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
sudo ip netns exec httptrace sh -c "echo 1 > /proc/sys/net/netfilter/nf_conntrack_acct"

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

go build -v . && sudo ip netns exec httptrace ./httptrace
*/
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"time"

	"example.com/httptrace/netdump"
	"example.com/httptrace/nettrace"
)

const (
	destURL   = "https://www.google.com/"
	localIP   = /*"192.168.88.2"*/ "192.168.99.1"
	httpVer   = 2  // 1 or 2
	proxy     = "" //https://10.10.10.101:9091"
	proxyCert = "" //"-----BEGIN CERTIFICATE-----\nMIIDVTCCAj2gAwIBAgIUPGtlx1k08RmWd9RxiCKTXYnAUkIwDQYJKoZIhvcNAQEL\nBQAwOjETMBEGA1UEAwwKemVkZWRhLmNvbTELMAkGA1UEBhMCVVMxFjAUBgNVBAcM\nDVNhbiBGcmFuY2lzY28wHhcNMjIwOTA3MTcwMDE0WhcNMzIwNjA2MTcwMDE0WjA6\nMRMwEQYDVQQDDAp6ZWRlZGEuY29tMQswCQYDVQQGEwJVUzEWMBQGA1UEBwwNU2Fu\nIEZyYW5jaXNjbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALQsi7IG\nM8KApujL71MJXbuPQNn/g+RItQeehaFRcqcCcpFW4k1YveMNdf5HReKlAfufFtaa\nIF368t33UlleblopLM8m8r9Ev1sSJOS1yYgU1HABjyw54LXBqT4tAf0xjlRaLn4L\nQBUAS0TTywTppGXtNwXpxqdDuQdigNskqzEFaGI52IQezfGt7L2CeeJ/YJNcbImR\neCXMPwTatUHLLE29Qv8GQQfy7TpCXdXVLvQAyfZJi7lY7DjPqBab5ocnVTRcEpKz\nFwH2+KTokQkU1UF614IveRF3ZOqqmrQvy1AdSvekFLIz2uP7xsfy3I3HNQcPJ4DI\n5vNzBaE/hF5xK40CAwEAAaNTMFEwHQYDVR0OBBYEFPxOB5cxsf89x6KdFSTTFV2L\nwta1MB8GA1UdIwQYMBaAFPxOB5cxsf89x6KdFSTTFV2Lwta1MA8GA1UdEwEB/wQF\nMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAFXqCJuq4ifMw3Hre7+X23q25jOb1nzd\n8qs+1Tij8osUC5ekD21x/k9g+xHvacoJIOzsAmpAPSnwXKMnvVdAeX6Scg1Bvejj\nTdXfNEJ7jcvDROUNjlWYjwiY+7ahDkj56nahwGjjUQdgCCzRiSYPOq6N1tRkn97a\ni6+jB8DnTSDnv5j8xiPDbWJ+nv2O1NNsoHS91UrTqkVXxNItrCdPPh21hzrTJxs4\noSf4wbaF5n3E2cPpSAaXBEyxBdXAqUCIhP0q9/pgBTYuJ+eW467u4xWqUVi4iBtN\nwVfYelYC2v03Rn433kv624oJDQ7MM5bDUv3nqPtkUys0ARwxs8tQCgg=\n-----END CERTIFICATE-----"
	ifName    = "httptrace-in"
	reqCount  = 1
	pcapFile  = "/tmp/httptrace.pcap"
	runPcap   = true
)

func init() {
	rand.Seed(time.Now().UnixNano())
	//nettrace.IDGenerator = nettrace.ShortUUID
}

func main() {
	cfg := nettrace.HTTPClientCfg{
		PreferHTTP2:    httpVer == 2,
		SourceIP:       net.ParseIP(localIP),
		SkipNameserver: nil,
		/*
			func(ipAddr net.IP, port uint16) (skip bool, reason string) {
				return true, "do not like this name server"
			},
		*/
		Proxy: func(reqURL *url.URL) (*url.URL, error) {
			if proxy == "" {
				return nil, nil
			}
			return url.Parse(proxy)
		},
		DisableKeepAlives: true, // Do not reuse connections
		ReqTimeout:        20 * time.Second,
		//TCPHandshakeTimeout: 5 * time.Second,
	}
	if proxyCert != "" {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM([]byte(proxyCert))
		cfg.TLSClientConfig = &tls.Config{
			RootCAs: caCertPool,
			// InsecureSkipVerify: true,
		}
	}
	opts := []nettrace.TraceOpt{
		&nettrace.WithLogging{},
		&nettrace.WithConntrack{},
		&nettrace.WithSockTrace{},
		&nettrace.WithDNSQueryTrace{},
		&nettrace.WithHTTPReqTrace{
			HeaderFields: nettrace.HdrFieldsOptDisabled,
		},
	}
	if runPcap {
		opts = append(opts, &nettrace.WithPacketCapture{
			Interfaces:        []string{ifName},
			IncludeICMP:       true,
			IncludeARP:        true,
			TCPWithoutPayload: false,
			//TotalSizeLimit:    8000,
		})
	}
	client, err := nettrace.NewHTTPClient(cfg, opts...)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer func() {
		fmt.Printf("Close: %v\n", client.Close())
	}()

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
		for err != nil {
			fmt.Printf("HTTP request error (%T): %v\n", err, err)
			if urlErr, ok := err.(*url.Error); ok {
				fmt.Printf("URL error: %v\n", urlErr)
			}
			err = errors.Unwrap(err)
		}
		fmt.Printf("HTTP request done: %v; %v\n", resp, err)

		if resp != nil && resp.Body != nil {
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}

		if resp != nil && resp.Body != nil {
			fmt.Println(resp.Body.Close())
		}
	}

	// Give PCAP some extra time get all the packets.
	time.Sleep(time.Second)

	httpTrace, pcaps, err := client.GetTrace(fmt.Sprintf("%s %s", "GET", destURL))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	traceInJson, err := json.MarshalIndent(httpTrace, "", "  ")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("HTTP Trace: %s\n", string(traceInJson))

	if runPcap {
		for _, pcap := range pcaps {
			err = pcap.WriteToFile(pcapFile)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Printf("Captured %d packets from interface %s (truncated: %t), "+
				"pcap written to %s\n", len(pcap.Packets), pcap.InterfaceName,
				pcap.Truncated, pcapFile)
		}
	}

	netDumper := &netdump.NetDumper{MaxDumpsPerTopic: 5}
	filename, err := netDumper.PublishHTTPTrace("test", httpTrace, pcaps)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("Published netdump to %s\n", filename)
}
