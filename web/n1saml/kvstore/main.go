package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"

	httpd "kvstore/http"
	"kvstore/store"

	"github.com/hashicorp/raft"
)

var (
	httpAddr  string
	raftAddr  string
	peerAddrs string
	nodeID    string
)

func init() {
	flag.StringVar(&httpAddr, "haddr", "", "HTTP bind address")
	flag.StringVar(&raftAddr, "raddr", "", "Raft bind address")
	flag.StringVar(&peerAddrs, "paddrs", "", "Comma-separated list of peer addresses")
	flag.StringVar(&nodeID, "id", "", "Raft Node ID")
}

func main() {
	flag.Parse()

	if httpAddr == "" || raftAddr == "" || peerAddrs == "" || nodeID == "" {
		flag.Usage()
		return
	}

	peers := make([]raft.Server, 0)
	for _, peer := range strings.Split(peerAddrs, ",") {
		arr := strings.SplitN(peer, ":", 2)
		peerID := arr[0]
		peerAddr := arr[1]

		peers = append(peers, raft.Server{
			ID:      raft.ServerID(peerID),
			Address: raft.ServerAddress(peerAddr),
		})
	}

	s := store.New(raftAddr, nodeID, peers)
	if err := s.Open(); err != nil {
		log.Fatal(err)
	}

	h := httpd.New(httpAddr, s)
	h.Start()

	terminate := make(chan os.Signal, 1)
	signal.Notify(terminate, os.Interrupt)
	<-terminate
}
