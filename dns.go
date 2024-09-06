package dns

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

/**
Design notes:

- Major:
  - DNS ID collisions could be bad? Could solve by adding client addr to key.
  - Handle custom resolving functions?
  - Nameservers should be configurable.

- Cache:
  - Need to expire cache entries.
  - Need to cap size of cache.
  - Could be a bottleneck?

- Minor:
  - Would not be able to handle multiple queries in a single packet.
  - Missing niche features like EDNS0, DNSSEC, etc?

Decisions:
 - Pre-allocate space for every query ID.. Given max DNS message size of 512 bytes,
   this theoretically could be 65536 * 512 bytes = 32MB of RAM... That's a lot. But we
   clean up the memory after requests.
**/

// Retry a DNS query if a resolver hasn't replied within the timeout.
const DnsRetryTimeout = 1 * time.Second

type Resolver interface {
	// Resolve a DNS query. This is a bit awkward - it's assumed the resolver
	// knows where to put the answer in a different implementation.
	Resolve(m Message)
}

type RemoteNameserver struct {
	answers chan Message

	// Address of the remote nameserver, including port.
	addr string

	// Re-use the same connection to the remote nameserver.
	conn net.Conn
}

// Create a remote nameserver resolver that will forward queries to addr,
// and send answers to the answers channel.
func NewRemoteNameserver(addr string, answers chan Message) Resolver {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		fmt.Printf("Some error %v", err)
	}

	go func() {
		for {
			b := make([]byte, 1024)
			n, err := conn.Read(b)
			if err != nil {
				log.Printf("Error: UDP read error: %v", err)
				continue
			}
			m := NewMessage(b[:n])
			answers <- m
		}
	}()

	return &RemoteNameserver{addr: addr, conn: conn, answers: answers}
}

// Send the query to the remote nameserver.
func (n *RemoteNameserver) Resolve(m Message) {
	n.conn.Write(m.Bytes())
}

type LocalCache struct {
	answers chan Message

	mu    sync.RWMutex
	cache map[string]Message
}

// A simple in-memory cache.
func NewLocalCache(answers chan Message) *LocalCache {
	return &LocalCache{
		answers: answers,
		cache:   make(map[string]Message),
	}
}

// The cache will answer the query if it is in the cache,
// else it will pass the query back to the server with Query=true.
func (l *LocalCache) Resolve(m Message) {
	l.mu.RLock()
	val, ok := l.cache[m.Questions[0].Name()]
	l.mu.RUnlock()
	if ok {
		newBuf := make([]byte, len(val.Bytes()))
		copy(newBuf, val.Bytes())
		msg := NewMessage(newBuf)
		msg.Header.SetId(m.Header.Id())
		l.answers <- msg
		return
	}

	// Return the query back to the server.
	l.answers <- m
}

// Add a message to the cache.
func (l *LocalCache) Add(m Message) {
	l.mu.Lock()
	l.cache[m.Questions[0].Name()] = m
	l.mu.Unlock()
}

type DnsServer struct {
	// The resolvers to use for DNS queries.
	resolvers []Resolver

	// Active queries. Indexed by the query ID.
	// The maximum ID for a query is 65536.
	activeQueries []QueryEntry

	// Answers from any resolver are sent here.
	answers chan Message

	// Local cache.
	cache *LocalCache
}

func NewDnsServer() *DnsServer {
	answers := make(chan Message)
	cache := NewLocalCache(answers)
	d := &DnsServer{
		resolvers: []Resolver{
			cache,
			NewRemoteNameserver("1.1.1.1:53", answers),
			NewRemoteNameserver("8.8.8.8:53", answers),
		},
		activeQueries: make([]QueryEntry, 65536),
		answers:       answers,
		cache:         cache,
	}

	return d
}

func (s *DnsServer) Start() {
	pc, err := net.ListenPacket("udp", ":53")
	if err != nil {
		log.Fatal(err)
	}
	defer pc.Close()

	go func() {
		for {
			buf := make([]byte, 1024)
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				continue
			}
			go s.handle(pc, addr, buf[:n])
		}
	}()

	go s.retryWorker()

	for answer := range s.answers {
		// If the query is no longer active, ignore the answer.
		if !s.activeQueries[answer.Header.Id()].active {
			fmt.Printf("Answer for inactive query #%v\n", answer.Header.Id())
			continue
		}

		// If we get a query back, it means the cache rejected it.
		// Mark the activeQuery as no cache and retry.
		if answer.Header.IsQuery() {
			s.retryQuery(answer.Header.Id())
			continue
		}

		// Answer the query.
		s.activeQueries[answer.Header.Id()].active = false
		_, err := pc.WriteTo(answer.Bytes(), s.activeQueries[answer.Header.Id()].clientAddr)
		s.activeQueries[answer.Header.Id()].Forget()
		if err != nil {
			fmt.Printf("Error writing to client: %v\n", err)
			continue
		}
		s.cache.Add(answer)
	}
}

// Handle a DNS query.
func (s *DnsServer) handle(pc net.PacketConn, addr net.Addr, buf []byte) {
	m := NewMessage(buf)
	if !s.activeQueries[m.Header.Id()].active {
		s.activeQueries[m.Header.Id()].active = true
		s.activeQueries[m.Header.Id()].msg = m
		s.activeQueries[m.Header.Id()].born = time.Now().UnixNano()
		s.activeQueries[m.Header.Id()].nsIdx = 0
		s.activeQueries[m.Header.Id()].nsTime = time.Now().UnixNano()
		s.activeQueries[m.Header.Id()].clientAddr = addr

		s.resolvers[s.activeQueries[m.Header.Id()].nsIdx].Resolve(m)

	} else {
		fmt.Printf("#%v: already active\n", m.Header.Id())
	}
}

// Periodically check for queries that have timed out and retry them.
func (s *DnsServer) retryWorker() {
	for {
		time.Sleep(100 * time.Millisecond)
		for id := range s.activeQueries {
			if s.activeQueries[id].active {
				if time.Since(time.Unix(0, s.activeQueries[id].nsTime)) > DnsRetryTimeout {
					s.retryQuery(uint16(id))
				}
			}
		}
	}
}

// Retry a query by sending it to the next resolver.
func (s *DnsServer) retryQuery(id uint16) {
	s.activeQueries[id].nsIdx++
	if s.activeQueries[id].nsIdx == uint8(len(s.resolvers)) {
		// Ran out of resolvers.
		fmt.Printf("#%v: dropped. Ran out of resolvers.\n", id)
		s.activeQueries[id].Forget()
		return
	}

	s.activeQueries[id].nsTime = time.Now().UnixNano()
	s.resolvers[s.activeQueries[id].nsIdx].Resolve(s.activeQueries[id].msg)
}

// Represents a single query.
type QueryEntry struct {
	// Whether the query is still active; pending an answer.
	active bool

	// The actual query message.
	msg Message

	// When the query was created.
	born int64

	// The address of the client that sent the query.
	clientAddr net.Addr

	// The index of the resolver that is currently handling the query.
	nsIdx uint8

	// The time the query was last sent to the current resolver.
	nsTime int64
}

// Returns the time the query has been active in milliseconds.
func (q *QueryEntry) InflightMs() int64 {
	return time.Since(time.Unix(0, q.born)).Milliseconds()
}

// Clear all information for this query entry.
func (q *QueryEntry) Forget() {
	q.active = false
	q.msg = Message{}
	q.born = 0
	q.clientAddr = nil
	q.nsIdx = 0
	q.nsTime = 0
}
