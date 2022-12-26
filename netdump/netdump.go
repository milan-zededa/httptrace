package netdump

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"time"

	"example.com/httptrace/nettrace"
)

const (
	// Directory where network dumps are persistently stored for later analysis.
	netdumpDir = "/persist/netdump"
)

// NetDumper publishes (writes to /persist/netdump) tar.gz archives containing network
// diagnostic information for post-mortem analysis of device connectivity issues.
type NetDumper struct {
	// MaxDumpsPerTopic : maximum number of archives with network diagnostic information
	// (aka network dumps) that can be persistent at the same time for a given topic.
	// NetDumper will remove the oldest network dump of a given topic before publishing
	// a new one that would otherwise exceed this limit.
	// By default (zero value), there is no limit.
	MaxDumpsPerTopic int
}

type fileToDump struct {
	srcPath string
	dstPath string
}

// Files created by EVE or the EVE installer that will be copied into each network dump.
var eveFilesToDump = [...]fileToDump{
	{
		srcPath: "/config/server",
		dstPath: "eve/controller.txt",
	},
	{
		srcPath: "/run/nim-current-state.dot",
		dstPath: "eve/nim-current-state.dot",
	},
	{
		srcPath: "/run/nim-intended-state.dot",
		dstPath: "eve/nim-intended-state.dot",
	},
	{
		srcPath: "/run/nim/DeviceNetworkStatus/global.json",
		dstPath: "eve/dns.json",
	},
	{
		srcPath: "/persist/status/nim/DevicePortConfigList/global.json",
		dstPath: "eve/dpcl.json",
	},
	{
		srcPath: "/run/domainmgr/AssignableAdapters/global.json",
		dstPath: "eve/aa.json",
	},
	{
		srcPath: "/run/wwan/config.json",
		dstPath: "eve/wwan-config.json",
	},
	{
		srcPath: "/run/wwan/status.json",
		dstPath: "eve/wwan-status.json",
	},
	{
		srcPath: "/run/wwan/metrics.json",
		dstPath: "eve/wwan-metrics.json",
	},
}

// Find references to routing tables from "ip rule list".
var rtLookupRE *regexp.Regexp

func init() {
	var err error
	rtLookupRE, err = regexp.Compile(" lookup (\\d+)")
	if err != nil {
		log.Fatal(err)
	}
}

// PublishHTTPTrace : publish HTTP trace obtained from a traced HTTP client,
// potentially also accompanied by a packet capture for some uplink interfaces.
// NetDumper will add some additional information into the dump, such as the current
// DPCL (DevicePortConfigList), DNS (DeviceNetworkStatus), ifconfig output, DHCP
// leases, wwan status and more.
// In order to avoid race conditions between microservices, each microservice
// should use different topic(s) (e.g. topic = microservice name).
// Topic name should not contain characters which are not suitable for filenames
// (across all OSes).
func (nd *NetDumper) PublishHTTPTrace(topic string,
	trace nettrace.HTTPTrace, pcaps []nettrace.PacketCapture) (filepath string, err error) {

	// Generate name for the network dump.
	// The layout should be such that string ordering corresponds to the time ordering.
	// Avoid characters which are not suitable for filenames (across all OSes).
	const timestampFormat = "2006-01-02T15-04-05"
	const extension = ".tgz"
	timestamp := time.Now().UTC()
	tarPrefix := topic + "-"
	tarFilename := fmt.Sprintf("%s%s%s",
		tarPrefix, timestamp.Format(timestampFormat), extension)
	filepath = path.Join(netdumpDir, tarFilename)

	// Create directories inside the archive and add the HTTP trace.
	traceInJson, err := json.MarshalIndent(trace, "", "  ")
	if err != nil {
		return "", fmt.Errorf("netdump: failed to marshal HTTP trace: %v", err)
	}
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
			dstPath: "linux",
			isDir:   true,
		},
		{
			dstPath: "nettrace.json",
			content: strings.NewReader(string(traceInJson)),
		},
	}

	// Add PCAPs into the archive.
	for _, pcap := range pcaps {
		pcapName := pcap.InterfaceName
		if pcap.Truncated {
			pcapName += "-truncated"
		}
		if !pcap.WithTCPPayload {
			pcapName += "-nopayload"
		}
		pcapName += ".pcap"
		buf := new(strings.Builder)
		err = pcap.WriteTo(buf)
		if err != nil {
			return "", fmt.Errorf("netdump: failed to write PCAP %s: %w", pcapName, err)
		}
		files = append(files, fileForTar{
			dstPath: path.Join("pcap", pcapName),
			content: strings.NewReader(buf.String()),
		})
	}

	// Try to get EVE version and include it in the network dump.
	var eveVer string
	if dirEntries, err := os.ReadDir("/config"); err == nil {
		for _, dirEntry := range dirEntries {
			if strings.HasPrefix(dirEntry.Name(), "origin.") {
				eveVer = strings.TrimPrefix(dirEntry.Name(), "origin.")
				break
			}
		}
	}
	if eveVer != "" {
		files = append(files, fileForTar{
			dstPath: "eve/version.txt",
			content: strings.NewReader(eveVer),
		})
	}

	// Include some files written by EVE or EVE installer that contain
	// information useful for network troubleshooting.
	for _, file := range eveFilesToDump {
		fileInfo, err := os.Stat(file.srcPath)
		if err != nil {
			// File is probably missing, skip it.
			continue
		}
		fileHandle, err := os.Open(file.srcPath)
		if err != nil {
			continue
		}
		defer fileHandle.Close()
		files = append(files, fileForTar{
			info:    fileInfo,
			dstPath: file.dstPath,
			content: fileHandle,
		})
	}

	// Capture and add into the archive some config/state data from the Linux network stack.
	if output, err := exec.Command("ifconfig").CombinedOutput(); err == nil {
		files = append(files, fileForTar{
			dstPath: "linux/ifconfig.txt",
			content: strings.NewReader(string(output)),
		})
	}
	if output, err := exec.Command("ip", "-s", "link").CombinedOutput(); err == nil {
		files = append(files, fileForTar{
			dstPath: "linux/iplink.txt",
			content: strings.NewReader(string(output)),
		})
	}
	if output, err := exec.Command("arp", "-a").CombinedOutput(); err == nil {
		files = append(files, fileForTar{
			dstPath: "linux/arp.txt",
			content: strings.NewReader(string(output)),
		})
	}
	routingTables := []string{"main"}
	if output, err := exec.Command("ip", "rule", "list").CombinedOutput(); err == nil {
		files = append(files, fileForTar{
			dstPath: "linux/iprule.txt",
			content: strings.NewReader(string(output)),
		})
		for _, rtLookup := range rtLookupRE.FindAllStringSubmatch(string(output), -1) {
			if len(rtLookup) == 2 {
				routingTables = append(routingTables, rtLookup[1])
			}
		}
	}
	for _, rt := range routingTables {
		cmd := exec.Command("ip", "route", "show", "table", rt)
		if output, err := cmd.CombinedOutput(); err == nil {
			files = append(files, fileForTar{
				dstPath: fmt.Sprintf("linux/iproute-%s.txt", rt),
				content: strings.NewReader(string(output)),
			})
		}
	}
	if netIfaces, err := net.Interfaces(); err == nil {
		for _, netIface := range netIfaces {
			cmd := exec.Command("dhcpcd", "-U", "-4", netIface.Name)
			output, err := cmd.CombinedOutput()
			if err != nil {
				continue
			}
			files = append(files, fileForTar{
				dstPath: fmt.Sprintf("linux/dhcp-lease-%s.txt", netIface.Name),
				content: strings.NewReader(string(output)),
			})
		}
	}
	var iptables = []string{"raw", "filter", "mangle", "nat"}
	for _, iptable := range iptables {
		cmd := exec.Command("iptables", "-L", "-v", "-n", "--line-numbers", "-t", iptable)
		if output, err := cmd.CombinedOutput(); err == nil {
			files = append(files, fileForTar{
				dstPath: fmt.Sprintf("linux/iptables-%s.txt", iptable),
				content: strings.NewReader(string(output)),
			})
		}
	}

	// Remove the oldest network dump if needed to avoid exceeding the count limit.
	if nd.MaxDumpsPerTopic > 0 {
		dirEntries, err := os.ReadDir(netdumpDir)
		if err != nil {
			return "", fmt.Errorf("netdump: failed to list directory %s: %w",
				netdumpDir, err)
		}
		var publishedDumps []string
		for _, dirEntry := range dirEntries {
			name := dirEntry.Name()
			if strings.HasPrefix(name, tarPrefix) && strings.HasSuffix(name, extension) {
				publishedDumps = append(publishedDumps, name)
			}
		}
		// publishedDumps are sorted in the ascending order (starting with oldest)
		// by ReadDir. We should keep at most the last nd.MaxDumpsPerTopic-1 dumps.
		for len(publishedDumps) >= nd.MaxDumpsPerTopic {
			dumpPath := path.Join(netdumpDir, publishedDumps[0])
			err := os.Remove(dumpPath)
			if err != nil {
				return "", fmt.Errorf("netdump: failed to remove older network dump %s: %w",
					dumpPath, err)
			}
			publishedDumps = publishedDumps[1:]
		}
	}

	// Write network dump into the persist partition.
	err = createTarGz(filepath, files)
	if err != nil {
		// Error is already formatted with "netdump:" prefix by createTarGz.
		return "", err
	}
	return filepath, nil
}
