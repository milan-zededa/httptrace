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

go build -v .
sudo ip netns exec httptrace ./httptrace
*/
package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/user"
	"path"
	"strings"
	"time"

	"example.com/httptrace/nettrace"
)

/*
- EVE will produce /persist/nettrace/<microservice>-<timestamp>.tar.gz that will contain:
	nettrace.json
	pcap/<ifname>.pcap...
	eve/version.txt nim-current/intended-state.dot (the same for zedrouter after refactor) controller.txt (host:port) dns.json dpcl.json aa.json
	wwan/status.json metrics.json config.json
	linux/ifconfig.txt iplink.txt arp.txt iprule.txt iproute-<table>.txt... dhcpcd-lease-<ifname>.txt...
*/

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
	tarFile   = "/tmp/nettrace.tgz"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type fileForTar struct {
	dstPath string
	info    fs.FileInfo
	isDir   bool
	content io.Reader
}

func createTarGz(tarPath string, files []fileForTar) (err error) {
	tarFile, err1 := os.Create(tarPath)
	if err1 != nil {
		return err1
	}
	defer tarFile.Close()
	gz := gzip.NewWriter(tarFile)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	for _, file := range files {
		var hdr *tar.Header
		content := file.content
		if file.info != nil {
			hdr, err = tar.FileInfoHeader(file.info, file.info.Name())
			if err != nil {
				return err
			}
		} else {
			now := time.Now()
			hdr = &tar.Header{
				Uid:        os.Getuid(),
				Gid:        os.Getgid(),
				ModTime:    now,
				AccessTime: now,
				ChangeTime: now,
			}
			if file.isDir {
				hdr.Typeflag = tar.TypeDir
				hdr.Mode = 0755 | int64(os.ModeDir)
			} else {
				hdr.Typeflag = tar.TypeReg
				hdr.Mode = 0664
				if file.content != nil {
					buf := new(strings.Builder)
					hdr.Size, err = io.Copy(buf, file.content)
					if err != nil {
						return err
					}
					content = strings.NewReader(buf.String())
				}
			}
			if whoami, err := user.Current(); err == nil {
				hdr.Uname = whoami.Username
				if group, err := user.LookupGroupId(whoami.Gid); err == nil {
					hdr.Gname = group.Name
				}
			}
		}
		hdr.Name = file.dstPath
		err = tw.WriteHeader(hdr)
		if err != nil {
			return err
		}
		if file.isDir {
			continue
		}
		if content != nil {
			_, err = io.Copy(tw, content)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func main() {
	cfg := nettrace.HTTPClientCfg{
		PreferHTTP2:    httpVer == 2,
		SourceIP:       net.ParseIP(localIP),
		SkipNameserver: nil,
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

	files := []fileForTar{
		{
			dstPath: "pcap",
			isDir:   true,
		},
		{
			dstPath: "eve",
			isDir:   true,
		},
		{
			dstPath: "wwan",
			isDir:   true,
		},
		{
			dstPath: "linux",
			isDir:   true,
		},
		{
			dstPath: "nettrace.json",
			content: strings.NewReader(string(traceInJson)),
		},
	}

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

			filename := pcap.InterfaceName
			if pcap.Truncated {
				filename += "-truncated"
			}
			filename += ".pcap"
			buf := new(strings.Builder)
			err = pcap.WriteTo(buf)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			files = append(files, fileForTar{
				dstPath: path.Join("pcap", filename),
				content: strings.NewReader(buf.String()),
			})
		}
	}

	err = createTarGz(tarFile, files)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("Network reported archived to %s\n", tarFile)
}
