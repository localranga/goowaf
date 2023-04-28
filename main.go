package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
	"jesuschrist19nig.com/goowaf/proxy"
	"jesuschrist19nig.com/goowaf/tampers"
	"jesuschrist19nig.com/goowaf/threading"
	"jesuschrist19nig.com/goowaf/waf_detection"
	"jesuschrist19nig.com/goowaf/arguments"
	"jesuschrist19nig.com/goowaf/wafs"
)

const (
	userAgentFile = "user_agents.txt"
)

type Payload struct {
	Type  string
	Value string
}

type WAFDetection struct {
	WAFs               []wafs.WAF
	Payloads           []Payload
	UserAgents         []string
	HTTPClient         *http.Client
	OutputFormat       string
	TamperingTechniques []tampers.Tamper
}

func main() {
	rand.Seed(time.Now().UnixNano())
	args := arguments.ParseArguments()

	if args.URL == "" && args.URLList == "" {
		fmt.Println("Please provide a URL or a list of URLs.")
		os.Exit(1)
	}

	var transport *http.Transport
	if args.UseTor {
		transport = proxy.GetTorTransport()
	} else if args.Proxy != "" {
		var err error
		transport, err = proxy.GetProxyTransport(args.Proxy)
		if err != nil {
			fmt.Printf("Error initializing proxy: %v\n", err)
			os.Exit(1)
		}
	}

	if args.URL != "" {
		err = wafDetection.ScanURL(args.URL)
	} else {
		err = wafDetection.ScanURLList(args.URLList, args.Concurrency)
	}

	if err != nil {
		fmt.Printf("Error scanning: %v\n", err)
		os.Exit(1)
	}
}

func NewWAFDetection(outputFormat string, transport *http.Transport) (*WAFDetection, error) {
	userAgents, err := loadUserAgents(userAgentFile)
	if err != nil {
		return nil, fmt.Errorf("Error loading user agents: %v", err)
	}

	httpClient := &http.Client{Transport: transport}

	wafs := wafs.LoadWAFs()

	return &WAFDetection{
		WAFs:         wafs,
		Payloads:     loadPayloads(),
		UserAgents:   userAgents,
		HTTPClient:   httpClient,
		OutputFormat: outputFormat,
		TamperingTechniques: []tampers.Tamper{},
			&UTF8EncodingTamper{},
			&SpaceToCommentTamper{},
			&ApostropheToDoubleEncodingTamper{},
			&RandomCaseTamper{},
		},
	}, nil
}
func (w *WAFDetection) matchHeader(headermatch string, attack bool) bool {
	var r *http.Response
	if attack {
		r = w.attackres
	} else {
		r = w.rq
	}
	if r == nil {
		return false
	}

	header, match := headermatch[0], headermatch[1]
	headerval := r.Header.Get(header)
	if headerval != "" {
		if header == "Set-Cookie" {
			headervals := strings.Split(headerval, ", ")
		} else {
			headervals := []string{headerval}
		}
		for _, headerval := range headervals {
			if match, _ := regexp.MatchString(match, headerval); match {
				return true
			}
		}
	}
	return false
}

func (w *WAFDetection) matchStatus(statuscode int, attack bool) bool {
	var r *http.Response
	if attack {
		r = w.attackres
	} else {
		r = w.rq
	}
	if r == nil {
		return false
	}
	if r.StatusCode == statuscode {
		return true
	}
	return false
}

func (w *WAFDetection) matchCookie(match string, attack bool) bool {
	return w.matchHeader([]string{"Set-Cookie", match}, attack)
}

func (w *WAFDetection) matchReason(reasoncode string, attack bool) bool {
	var r *http.Response
	if attack {
		r = w.attackres
	} else {
		r = w.rq
	}
	if r == nil {
		return false
	}
	if r.Status == reasoncode {
		return true
	}
	return false
}

func (w *WAFDetection) matchContent(regex string, attack bool) bool {
	var r *http.Response
	if attack {
		r = w.attackres
	} else {
		r = w.rq
	}
	if r == nil {
		return false
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return false
	}
	defer r.Body.Close()

	if match, _ := regexp.MatchString(regex, string(body)); match {
		return true
	}
	return false
}
func(w * WAFDetection) ScanURL(url string) error {
    // Choose a random user agent
    userAgent: = w.UserAgents[rand.Intn(len(w.UserAgents))]

    // Iterate over WAFs and payloads
    for _,
    waf: = range w.WAFs {
        for _, payload: = range w.Payloads {
            // Apply tampering techniques
            for _, tamper: = range w.TamperingTechniques {
                tamperedPayload, err: = tamper.Tamper(payload.Value)
                if err != nil {
                    return err
                }

                // Send the request with the tampered payload and user agent
                resp, err: = w.sendRequest(url, tamperedPayload, userAgent)
                if err != nil {
                    return err
                }

                // Check the response for WAF detection patterns
                if w.detectWAF(resp, waf) {
                    if w.OutputFormat == "json" {
                        jsonOutput, err: = json.Marshal(map[string] interface {} {
                            "url": url,
                            "waf": waf.Name,
                                "type": payload.Type,
                        })
                        if err != nil {
                            return err
                        }
                        fmt.Println(string(jsonOutput))
                    } else {
                        fmt.Printf("Detected WAF: %s\n", waf.Name)
                    }
                    break
                }
            }
        }
    }
    return nil
}

func (w *WAFDetection) ScanURLList(listPath string, concurrency int) error {
    content, err := ioutil.ReadFile(listPath)
    if err != nil {
        return fmt.Errorf("Error reading URL list: %v", err)
    }
    urls := strings.Split(string(content), "\n")
    concurrentScanner := NewConcurrentScanner(w, concurrency)
    concurrentScanner.ScanURLs(urls)

    return nil
}


func(w * WAFDetection) sendRequest(url, payload, userAgent string)( * http.Response, error) {
    req, err: = http.NewRequest("GET", url, nil)
    if err != nil {
            return nil, fmt.Errorf("Error creating request: %v", err)
        }
        // Add the tampered payload to the request URL
    req.URL.RawQuery = payload

    // Set the User-Agent header
    req.Header.Set("User-Agent", userAgent)

    resp, err: = w.HTTPClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("Error sending request: %v", err)
    }

    return resp, nil
}

func(w * WAFDetection) detectWAF(resp * http.Response, waf WAF) bool {
    // Check the response for WAF detection patterns
    for _, pattern: = range waf.DetectionPatterns {
        if strings.Contains(resp.Header.Get("Server"), pattern) {
            return true
        }
    }
    return false
}


func loadPayloads()[] Payload {
    // Load payloads from files or other sources
    return [] Payload {
        {
            Type: "SQL injection",
            Value: "1' OR '1'='1",
        },
    }
}

func loadUserAgents(filename string)([] string, error) {
    content, err: = ioutil.ReadFile(filename)
    if err != nil {
        return nil, fmt.Errorf("Error reading user agents file: %v", err)
    }
    return strings.Split(string(content), "\n"), nil
}