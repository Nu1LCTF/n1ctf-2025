package main

import (
	"flag"
	"log"
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
)

func HealthCheck(c *gin.Context) {
	params := make(map[string]string)
	_ = c.ShouldBindJSON(&params)

	args := make([]string, 0)
	args = append(args, url)

	if len(params) > 0 {
		for k, v := range params {
			args = append(args, k, v)
		}
	}

	cmd := exec.Command("curl", args...)
	if err := cmd.Run(); err != nil {
		c.String(http.StatusInternalServerError, "FAIL")
	} else {
		c.String(http.StatusOK, "OK")
	}
}

var (
	addr string
	url  string
)

func init() {
	flag.StringVar(&addr, "addr", "", "HTTP Bind address")
	flag.StringVar(&url, "url", "", "Healthcheck URL")
}

func main() {
	flag.Parse()

	if addr == "" || url == "" {
		flag.Usage()
		return
	}

	r := gin.Default()
	r.Any("/healthcheck", HealthCheck)
	log.Fatal(r.Run(addr))
}
