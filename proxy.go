package proxy

import (
	"net/http"
	"net/url"
)

func GetProxyTransport(proxyAddress string) (*http.Transport, error) {
	proxyURL, err := url.Parse(proxyAddress)
	if err != nil {
		return nil, err
	}

	return &http.Transport{Proxy: http.ProxyURL(proxyURL)}, nil
}

func GetTorTransport() *http.Transport {
	return &http.Transport{Proxy: http.ProxyURL(&url.URL{
		Scheme: "socks5",
		Host:   "localhost:9050",
	})}
}