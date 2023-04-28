package threading

import (
	"fmt"
	"sync"
)

type ConcurrentScanner struct {
	wafDetection *waf_detection.WAFDetection
	maxWorkers   int
}

func NewConcurrentScanner(wafDetection *waf_detection.WAFDetection, maxWorkers int) *ConcurrentScanner {
	return &ConcurrentScanner{
		wafDetection: wafDetection,
		maxWorkers:   maxWorkers,
	}
}

func (cs *ConcurrentScanner) ScanURLs(urls []string) {
	var wg sync.WaitGroup
	urlCh := make(chan string, cs.maxWorkers)

	// Start worker Goroutines
	for i := 0; i < cs.maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urlCh {
				if err := cs.wafDetection.ScanURL(url); err != nil {
					fmt.Printf("Error scanning URL %s: %v\n", url, err)
				}
			}
		}()
	}

	// Feed URLs to the workers
	for _, url := range urls {
		urlCh <- url
	}

	close(urlCh)
	wg.Wait()
}
