package waf_detection

import (
	"net/http"
	"regexp"
)

type WAF struct {
	Name              string
	CheckFunc         WAFCheck
}

type WAFCheck func(*http.Response) bool

func LoadWAFs() []WAF {
	return []WAF{
		{
			Name:      "aeSecure",
			CheckFunc: isWAFaeSecure,
		},
		// Add more WAF instances here
	}
}

func isWAFaeSecure(resp *http.Response) bool {
	pattern1 := regexp.MustCompile(`aeSecure-code`)
	pattern2 := regexp.MustCompile(`aesecure_denied\.png`)

	if pattern1.MatchString(resp.Header.Get("aeSecure-code")) {
		return true
	}
	for _, value := range resp.Header["Content"] {
		if pattern2.MatchString(value) {
			return true
		}
	}
	return false
}
