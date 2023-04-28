package arguments

import (
	"flag"
)

type Arguments struct {
	URL          string
	URLList      string
	OutputFormat string
	Concurrency  int
	Proxy        string
	UseTor       bool
}

func ParseArguments() *Arguments {
	urlFlag := flag.String("u", "", "URL to scan")
	listFlag := flag.String("l", "", "List of URLs to scan")
	outputFormatFlag := flag.String("o", "txt", "Output format: txt or json")
	concurrencyFlag := flag.Int("c", 5, "Number of concurrent workers for scanning")
	proxyFlag := flag.String("p", "", "HTTP/HTTPS proxy address (format: http://proxy:port or https://proxy:port)")
	useTorFlag := flag.Bool("tor", false, "Use Tor as a proxy (requires Tor to be installed and running)")

	flag.Parse()

	return &Arguments{
		URL:          *urlFlag,
		URLList:      *listFlag,
		OutputFormat: *outputFormatFlag,
		Concurrency:  *concurrencyFlag,
		Proxy:        *proxyFlag,
		UseTor:       *useTorFlag,
	}
}
