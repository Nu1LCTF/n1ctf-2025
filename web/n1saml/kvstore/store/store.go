package store

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

type Command struct {
	Op    string `json:"op,omitempty"`
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

type Node struct {
	ID      string `json:"id"`
	Address string `json:"address"`
}

type StoreStatus struct {
	Me        Node   `json:"me"`
	Leader    Node   `json:"leader"`
	Followers []Node `json:"followers"`
}

type Store struct {
	addr    string
	nodeID  string
	servers []raft.Server

	mu sync.Mutex
	m  map[string]string

	raft   *raft.Raft
	logger *log.Logger
}

func New(addr string, nodeID string, servers []raft.Server) *Store {
	return &Store{
		addr:    addr,
		nodeID:  nodeID,
		servers: servers,

		m:      make(map[string]string),
		logger: log.Default(),
	}
}

func (s *Store) Open() error {
	config := raft.DefaultConfig()
	config.LocalID = raft.ServerID(s.nodeID)

	addr, err := net.ResolveTCPAddr("tcp", s.addr)
	if err != nil {
		return err
	}

	transport, err := raft.NewTCPTransport(s.addr, addr, 3, 10*time.Second, os.Stderr)
	if err != nil {
		return err
	}

	logStore := raft.NewInmemStore()
	stableStore := raft.NewInmemStore()
	snapshots := raft.NewInmemSnapshotStore()

	ra, err := raft.NewRaft(config, (*fsm)(s), logStore, stableStore, snapshots, transport)
	if err != nil {
		return err
	}

	s.raft = ra
	configuration := raft.Configuration{
		Servers: s.servers,
	}
	ra.BootstrapCluster(configuration)

	return nil
}

func (s *Store) Get(key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[key], nil
}

func (s *Store) Set(key, value string) error {
	if s.raft.State() != raft.Leader {
		return fmt.Errorf("not leader")
	}

	if v, _ := s.Get(key); v != "" {
		return fmt.Errorf("key already exists")
	}

	c := &Command{
		Op:    "set",
		Key:   key,
		Value: value,
	}
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}

	f := s.raft.Apply(b, 10*time.Second)
	return f.Error()
}

func (s *Store) Flush() error {
	if s.raft.State() != raft.Leader {
		return fmt.Errorf("not leader")
	}

	c := &Command{
		Op: "flush",
	}
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}

	f := s.raft.Apply(b, 10*time.Second)
	return f.Error()
}

func (s *Store) Status() StoreStatus {
	leaderServerAddr, leaderId := s.raft.LeaderWithID()
	leader := Node{
		ID:      string(leaderId),
		Address: string(leaderServerAddr),
	}

	servers := s.raft.GetConfiguration().Configuration().Servers
	followers := []Node{}
	me := Node{
		Address: s.addr,
	}

	for _, server := range servers {
		if server.ID != leaderId {
			followers = append(followers, Node{
				ID:      string(server.ID),
				Address: string(server.Address),
			})
		}

		if string(server.Address) == s.addr {
			me = Node{
				ID:      string(server.ID),
				Address: string(server.Address),
			}
		}
	}

	status := StoreStatus{
		Me:        me,
		Leader:    leader,
		Followers: followers,
	}

	return status
}

type fsm Store

func (f *fsm) Apply(l *raft.Log) interface{} {
	var c Command
	if err := json.Unmarshal(l.Data, &c); err != nil {
		log.Fatal("failed to unmarshal command:", err)
	}

	switch c.Op {
	case "set":
		return f.applySet(c.Key, c.Value)
	case "flush":
		return f.applyFlush()
	default:
		log.Println("unrecognized command op:", c.Op)
		return nil
	}
}

func (f *fsm) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	o := make(map[string]string)
	for k, v := range f.m {
		o[k] = v
	}

	return &fsmSnapshot{store: o}, nil
}

func (f *fsm) Restore(rc io.ReadCloser) error {
	o := make(map[string]string)
	if err := json.NewDecoder(rc).Decode(&o); err != nil {
		return err
	}

	f.m = o
	return nil
}

func (f *fsm) applySet(key, value string) interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[key] = value
	return nil
}

func (f *fsm) applyFlush() interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m = make(map[string]string)
	return nil
}

type fsmSnapshot struct {
	store map[string]string
}

func (f *fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	err := func() error {
		b, err := json.Marshal(f.store)
		if err != nil {
			return err
		}

		if _, err := sink.Write(b); err != nil {
			return err
		}

		return sink.Close()
	}()

	if err != nil {
		sink.Cancel()
	}

	return err
}

func (f *fsmSnapshot) Release() {}
