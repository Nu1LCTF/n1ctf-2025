package main

import (
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
)

var (
	addr string
	urls string
	
	backends []string
	current  uint32
)

func init() {
	flag.StringVar(&addr, "addr", "", "HTTP bind address")
	flag.StringVar(&urls, "urls", "", "Comma-separated list of backend URLs")
}

func main() {
	flag.Parse()

	if addr == "" || urls == "" {
		flag.Usage()
		return
	}

	for _, v := range strings.Split(urls, ",") {
		backends = append(backends, v)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		backend := nextBackend()
		target, _ := url.Parse(backend)
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ServeHTTP(w, r)
	})

	log.Fatal(http.ListenAndServe(addr, nil))
}

func nextBackend() string {
	idx := atomic.AddUint32(&current, 1)
	return backends[idx%uint32(len(backends))]
}
