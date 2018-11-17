// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package discv5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

const (
	ticketTimeBucketLen = time.Minute
	timeWindow          = 10 // * ticketTimeBucketLen
	wantTicketsInWindow = 10
	collectFrequency    = time.Second * 30
	registerFrequency   = time.Second * 60
	maxCollectDebt      = 10
	maxRegisterDebt     = 5
	keepTicketConst     = time.Minute * 10
	keepTicketExp       = time.Minute * 5
	targetWaitTime      = time.Minute * 10
	topicQueryTimeout   = time.Second * 5
	topicQueryResend    = time.Minute
	// topic radius detection
	maxRadius           = 0xffffffffffffffff
	radiusTC            = time.Minute * 20
	radiusBucketsPerBit = 8
	minSlope            = 1
	minPeakSize         = 40
	maxNoAdjust         = 20
	lookupWidth         = 8
	minRightSum         = 20
	searchForceQuery    = 4
)

// 因为时间是单调增长的，所以每个topic的的入场券也就是单调增长的。
// 这里采用时间来做 topic有效性的索引，让一个指针指向当前失效和有效的分隔点
// timeBucket represents absolute monotonic time in minutes.
// It is used as the index into the per-topic ticket buckets.
type timeBucket int

/* 这里同一个topic的发起人所注册的  n个topic打成一个包，这个包就叫做ticket。这批topic要么一起可以被适用，要么一起停用 */
/* 这里保存在一起后，怎么查找呢某个具体的topic呢？ 在ticketRef中，idx就是某个topic在 topics和regtime的索引 */
type ticket struct {
	/* 同一批注册的所有topic */
	topics []Topic
	/* 按照topics的顺序，保存每个topic的注册时间 */
	regTime []mclock.AbsTime // Per-topic local absolute time when the ticket can be used.

	// The serial number that was issued by the server.
	serial uint32
	// Used by registrar, tracks absolute time when the ticket was created.
	/* 这批topic 统一发布的时间，也就是将这批topic打成一个包，一起开始可以使用的上线时间 */
	issueTime mclock.AbsTime

	// Fields used only by registrants
	/* 该入场券的登记员 */
	node *Node // the registrar node that signed this ticket

	/* 该入场券中 关联了多少个topic，也就是topic的个数 */
	refCnt int // tracks number of topics that will be registered using this ticket

	/* 登记员对该入场券的签名 */
	pong []byte // encoded pong packet signed by the registrar
}

// ticketRef refers to a single topic in a ticket.
/* 由于可以发布很多入场券，所以在定位某一个topic时，需要指明是ticket的指针 */
type ticketRef struct {

	/* 这存储的只是 ticket的索引索引 */
	t   *ticket
	idx int // index of the topic in t.topics and t.regTime
}

func (ref ticketRef) topic() Topic {
	return ref.t.topics[ref.idx]
}

func (ref ticketRef) topicRegTime() mclock.AbsTime {
	return ref.t.regTime[ref.idx]
}

func pongToTicket(localTime mclock.AbsTime, topics []Topic, node *Node, p *ingressPacket) (*ticket, error) {
	wps := p.data.(*pong).WaitPeriods
	if len(topics) != len(wps) {
		return nil, fmt.Errorf("bad wait period list: got %d values, want %d", len(topics), len(wps))
	}
	if rlpHash(topics) != p.data.(*pong).TopicHash {
		return nil, fmt.Errorf("bad topic hash")
	}
	t := &ticket{
		issueTime: localTime,
		node:      node,
		topics:    topics,
		pong:      p.rawData,
		regTime:   make([]mclock.AbsTime, len(wps)),
	}
	// Convert wait periods to local absolute time.
	for i, wp := range wps {
		t.regTime[i] = localTime + mclock.AbsTime(time.Second*time.Duration(wp))
	}
	return t, nil
}

/**
 * @param t 节点所有订阅号的轮询周期与注册时间(表明订阅可以开始接受)
 * @param pong  发送的数据包
 * @return pong 发送的数据包
 */
func ticketToPong(t *ticket, pong *pong) {

	//过期时间就是当前时间
	pong.Expiration = uint64(t.issueTime / mclock.AbsTime(time.Second))

	// 对方订阅号编码规则
	pong.TopicHash = rlpHash(t.topics)

	pong.TicketSerial = t.serial

	// 获取每个topic的订阅消息频率
	pong.WaitPeriods = make([]uint32, len(t.regTime))

	for i, regTime := range t.regTime {

		//更新 订阅消息的频率
		pong.WaitPeriods[i] = uint32(time.Duration(regTime-t.issueTime) / time.Second)
	}
}

// ticket存储器，也就是topic的 超时管理器
type ticketStore struct {
	// radius detector and target address generator
	// exists for both searched and registered topics
	/* 用于半径侦查，保存了里该topic最近的n个节点。广播时不是全网广播，而是在该半径内广播 */
	radius map[Topic]*topicRadius

	// Contains buckets (for each absolute minute) of tickets
	// that can be used in that minute.
	// This is only set if the topic is being registered.

	/* 按照topic对ticket做分类 */
	tickets map[Topic]*topicTickets

	/* 已经注册的topic */
	regQueue []Topic // Topic registration queue for round robin attempts

	/* 已经注册的topic内容 */
	regSet map[Topic]struct{} // Topic registration queue contents for fast filling

	/* 保存每个节点 对应的入场券 */
	nodes map[*Node]*ticket

	/* 每个节点最近一次 接受topic的内容 */
	nodeLastReq map[*Node]reqInfo
	/* 最近一次注册topic的时间 */
	lastBucketFetched timeBucket

	/* ticket中，当前正在使用的topic的下一个 topic是什么 */
	nextTicketCached *ticketRef
	/* ticket中，当前正在使用的topic的下一个 topic的注册时间 */
	nextTicketReg mclock.AbsTime
	/* 查询topic的请求的缓存 */
	searchTopicMap map[Topic]searchTopic
	/* 暂时不知道要做什么 */
	nextTopicQueryCleanup mclock.AbsTime
	/* 保存查询内容：向哪些个节点发送了哪些请求 */
	queriesSent map[*Node]map[common.Hash]sentQuery
}

/* 查询topic返回的结果结构 */
type searchTopic struct {
	foundChn chan<- *Node
}

/* 查询请求 */
type sentQuery struct {
	sent   mclock.AbsTime
	lookup lookupInfo
}

/* 每个注册成功的topic对应的所有入场券。 */
/* 不管这个topic是本地由本地发布的还是由其他节点发布的，这要这个topic在本地节点注册成功，就代表其可以使用了 */
type topicTickets struct {
	buckets map[timeBucket][]ticketRef

	/* 下次查询时间 */
	nextLookup mclock.AbsTime
	/* 下次注册时间 */
	nextReg mclock.AbsTime
}

func newTicketStore() *ticketStore {
	return &ticketStore{
		/* 一个topic的半径对象 */
		radius:  make(map[Topic]*topicRadius),
		tickets: make(map[Topic]*topicTickets),
		/* 已经注册的topic内容 */
		regSet: make(map[Topic]struct{}),
		/* 每个节点对应的ticket（也存储每个节点注册的所有topic） */
		nodes: make(map[*Node]*ticket),
		/* 每个节点的最新请求  */
		nodeLastReq: make(map[*Node]reqInfo),
		/* 每个topic查询得到结构后 应该保存在哪里 */
		searchTopicMap: make(map[Topic]searchTopic),
		/*  */
		queriesSent: make(map[*Node]map[common.Hash]sentQuery),
	}
}

// addTopic starts tracking a topic. If register is true,
// the local node will register the topic and tickets will be collected.
func (s *ticketStore) addTopic(topic Topic, register bool) {
	log.Trace("Adding discovery topic", "topic", topic, "register", register)
	if s.radius[topic] == nil {
		/* 定义该topic的广播半径内容 */
		s.radius[topic] = newTopicRadius(topic)
	}
	/* 判断是否需要注册，已经注册的topic一定有对应的入场券，入场券代表了一个topic注册的有效性，和使用时间 */
	if register && s.tickets[topic] == nil {
		s.tickets[topic] = &topicTickets{buckets: make(map[timeBucket][]ticketRef)}
	}
}

func (s *ticketStore) addSearchTopic(t Topic, foundChn chan<- *Node) {
	s.addTopic(t, false)
	if s.searchTopicMap[t].foundChn == nil {
		s.searchTopicMap[t] = searchTopic{foundChn: foundChn}
	}
}

func (s *ticketStore) removeSearchTopic(t Topic) {
	if st := s.searchTopicMap[t]; st.foundChn != nil {
		delete(s.searchTopicMap, t)
	}
}

// removeRegisterTopic deletes all tickets for the given topic.
/* 取消该topic 对应的所有入场券 */
func (s *ticketStore) removeRegisterTopic(topic Topic) {
	log.Trace("Removing discovery topic", "topic", topic)
	if s.tickets[topic] == nil {
		log.Warn("Removing non-existent discovery topic", "topic", topic)
		return
	}
	for _, list := range s.tickets[topic].buckets {
		for _, ref := range list {
			ref.t.refCnt--
			if ref.t.refCnt == 0 {
				delete(s.nodes, ref.t.node)
				delete(s.nodeLastReq, ref.t.node)
			}
		}
	}
	delete(s.tickets, topic)
}

/* 获取当前节点，在本地已经注册成功的所有topic。只要注册成功，必然对应相应的入场券 */
func (s *ticketStore) regTopicSet() []Topic {

	/* 根据入场券个数来决定注册成功的topic的个数 */
	topics := make([]Topic, 0, len(s.tickets))
	for topic := range s.tickets {
		topics = append(topics, topic)
	}
	return topics
}

// nextRegisterLookup returns the target of the next lookup for ticket collection.
func (s *ticketStore) nextRegisterLookup() (lookupInfo, time.Duration) {
	// Queue up any new topics (or discarded ones), preserving iteration order
	for topic := range s.tickets {
		if _, ok := s.regSet[topic]; !ok {
			s.regQueue = append(s.regQueue, topic)
			s.regSet[topic] = struct{}{}
		}
	}
	// Iterate over the set of all topics and look up the next suitable one
	for len(s.regQueue) > 0 {
		// Fetch the next topic from the queue, and ensure it still exists
		topic := s.regQueue[0]
		s.regQueue = s.regQueue[1:]
		delete(s.regSet, topic)

		if s.tickets[topic] == nil {
			continue
		}
		// If the topic needs more tickets, return it
		if s.tickets[topic].nextLookup < mclock.Now() {
			next, delay := s.radius[topic].nextTarget(false), 100*time.Millisecond
			log.Trace("Found discovery topic to register", "topic", topic, "target", next.target, "delay", delay)
			return next, delay
		}
	}
	// No registration topics found or all exhausted, sleep
	delay := 40 * time.Second
	log.Trace("No topic found to register", "delay", delay)
	return lookupInfo{}, delay
}

func (s *ticketStore) nextSearchLookup(topic Topic) lookupInfo {
	tr := s.radius[topic]
	target := tr.nextTarget(tr.radiusLookupCnt >= searchForceQuery)
	if target.radiusLookup {
		tr.radiusLookupCnt++
	} else {
		tr.radiusLookupCnt = 0
	}
	return target
}

// ticketsInWindow returns the tickets of a given topic in the registration window.
func (s *ticketStore) ticketsInWindow(topic Topic) []ticketRef {
	// Sanity check that the topic still exists before operating on it
	if s.tickets[topic] == nil {
		log.Warn("Listing non-existing discovery tickets", "topic", topic)
		return nil
	}
	// Gather all the tickers in the next time window
	var tickets []ticketRef

	buckets := s.tickets[topic].buckets
	for idx := timeBucket(0); idx < timeWindow; idx++ {
		tickets = append(tickets, buckets[s.lastBucketFetched+idx]...)
	}
	log.Trace("Retrieved discovery registration tickets", "topic", topic, "from", s.lastBucketFetched, "tickets", len(tickets))
	return tickets
}

func (s *ticketStore) removeExcessTickets(t Topic) {
	tickets := s.ticketsInWindow(t)
	if len(tickets) <= wantTicketsInWindow {
		return
	}
	sort.Sort(ticketRefByWaitTime(tickets))
	for _, r := range tickets[wantTicketsInWindow:] {
		s.removeTicketRef(r)
	}
}

type ticketRefByWaitTime []ticketRef

// Len is the number of elements in the collection.
func (s ticketRefByWaitTime) Len() int {
	return len(s)
}

func (r ticketRef) waitTime() mclock.AbsTime {
	return r.t.regTime[r.idx] - r.t.issueTime
}

// Less reports whether the element with
// index i should sort before the element with index j.
func (s ticketRefByWaitTime) Less(i, j int) bool {
	return s[i].waitTime() < s[j].waitTime()
}

// Swap swaps the elements with indexes i and j.
func (s ticketRefByWaitTime) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s *ticketStore) addTicketRef(r ticketRef) {
	topic := r.t.topics[r.idx]
	tickets := s.tickets[topic]
	if tickets == nil {
		log.Warn("Adding ticket to non-existent topic", "topic", topic)
		return
	}
	bucket := timeBucket(r.t.regTime[r.idx] / mclock.AbsTime(ticketTimeBucketLen))
	tickets.buckets[bucket] = append(tickets.buckets[bucket], r)
	r.t.refCnt++

	min := mclock.Now() - mclock.AbsTime(collectFrequency)*maxCollectDebt
	if tickets.nextLookup < min {
		tickets.nextLookup = min
	}
	tickets.nextLookup += mclock.AbsTime(collectFrequency)

	//s.removeExcessTickets(topic)
}

func (s *ticketStore) nextFilteredTicket() (*ticketRef, time.Duration) {
	now := mclock.Now()
	for {
		ticket, wait := s.nextRegisterableTicket()
		if ticket == nil {
			return ticket, wait
		}
		log.Trace("Found discovery ticket to register", "node", ticket.t.node, "serial", ticket.t.serial, "wait", wait)

		regTime := now + mclock.AbsTime(wait)
		topic := ticket.t.topics[ticket.idx]
		if s.tickets[topic] != nil && regTime >= s.tickets[topic].nextReg {
			return ticket, wait
		}
		s.removeTicketRef(*ticket)
	}
}

func (s *ticketStore) ticketRegistered(ref ticketRef) {
	now := mclock.Now()

	topic := ref.t.topics[ref.idx]
	tickets := s.tickets[topic]
	min := now - mclock.AbsTime(registerFrequency)*maxRegisterDebt
	if min > tickets.nextReg {
		tickets.nextReg = min
	}
	tickets.nextReg += mclock.AbsTime(registerFrequency)
	s.tickets[topic] = tickets

	s.removeTicketRef(ref)
}

// nextRegisterableTicket returns the next ticket that can be used
// to register.
//
// If the returned wait time <= zero the ticket can be used. For a positive
// wait time, the caller should requery the next ticket later.
//
// A ticket can be returned more than once with <= zero wait time in case
// the ticket contains multiple topics.
func (s *ticketStore) nextRegisterableTicket() (*ticketRef, time.Duration) {
	now := mclock.Now()
	if s.nextTicketCached != nil {
		return s.nextTicketCached, time.Duration(s.nextTicketCached.topicRegTime() - now)
	}

	for bucket := s.lastBucketFetched; ; bucket++ {
		var (
			empty      = true    // true if there are no tickets
			nextTicket ticketRef // uninitialized if this bucket is empty
		)
		for _, tickets := range s.tickets {
			//s.removeExcessTickets(topic)
			if len(tickets.buckets) != 0 {
				empty = false

				list := tickets.buckets[bucket]
				for _, ref := range list {
					//debugLog(fmt.Sprintf(" nrt bucket = %d node = %x sn = %v wait = %v", bucket, ref.t.node.ID[:8], ref.t.serial, time.Duration(ref.topicRegTime()-now)))
					if nextTicket.t == nil || ref.topicRegTime() < nextTicket.topicRegTime() {
						nextTicket = ref
					}
				}
			}
		}
		if empty {
			return nil, 0
		}
		if nextTicket.t != nil {
			s.nextTicketCached = &nextTicket
			return &nextTicket, time.Duration(nextTicket.topicRegTime() - now)
		}
		s.lastBucketFetched = bucket
	}
}

// removeTicket removes a ticket from the ticket store
func (s *ticketStore) removeTicketRef(ref ticketRef) {
	log.Trace("Removing discovery ticket reference", "node", ref.t.node.ID, "serial", ref.t.serial)

	// Make nextRegisterableTicket return the next available ticket.
	s.nextTicketCached = nil

	topic := ref.topic()
	tickets := s.tickets[topic]

	if tickets == nil {
		log.Trace("Removing tickets from unknown topic", "topic", topic)
		return
	}
	bucket := timeBucket(ref.t.regTime[ref.idx] / mclock.AbsTime(ticketTimeBucketLen))
	list := tickets.buckets[bucket]
	idx := -1
	for i, bt := range list {
		if bt.t == ref.t {
			idx = i
			break
		}
	}
	if idx == -1 {
		panic(nil)
	}
	list = append(list[:idx], list[idx+1:]...)
	if len(list) != 0 {
		tickets.buckets[bucket] = list
	} else {
		delete(tickets.buckets, bucket)
	}
	ref.t.refCnt--
	if ref.t.refCnt == 0 {
		delete(s.nodes, ref.t.node)
		delete(s.nodeLastReq, ref.t.node)
	}
}

type lookupInfo struct {
	/* 从哪个节点查询 */
	target common.Hash
	/* 查询的topic名称 */
	topic Topic
	/* 是否允许节点进行半径查询 */
	radiusLookup bool
}

type reqInfo struct {
	pingHash []byte
	lookup   lookupInfo
	time     mclock.AbsTime
}

// returns -1 if not found
func (t *ticket) findIdx(topic Topic) int {
	for i, tt := range t.topics {
		if tt == topic {
			return i
		}
	}
	return -1
}

func (s *ticketStore) registerLookupDone(lookup lookupInfo, nodes []*Node, ping func(n *Node) []byte) {
	now := mclock.Now()
	for i, n := range nodes {
		if i == 0 || (binary.BigEndian.Uint64(n.sha[:8])^binary.BigEndian.Uint64(lookup.target[:8])) < s.radius[lookup.topic].minRadius {
			if lookup.radiusLookup {
				if lastReq, ok := s.nodeLastReq[n]; !ok || time.Duration(now-lastReq.time) > radiusTC {
					s.nodeLastReq[n] = reqInfo{pingHash: ping(n), lookup: lookup, time: now}
				}
			} else {
				if s.nodes[n] == nil {
					s.nodeLastReq[n] = reqInfo{pingHash: ping(n), lookup: lookup, time: now}
				}
			}
		}
	}
}

func (s *ticketStore) searchLookupDone(lookup lookupInfo, nodes []*Node, query func(n *Node, topic Topic) []byte) {
	now := mclock.Now()
	for i, n := range nodes {
		if i == 0 || (binary.BigEndian.Uint64(n.sha[:8])^binary.BigEndian.Uint64(lookup.target[:8])) < s.radius[lookup.topic].minRadius {
			if lookup.radiusLookup {
				if lastReq, ok := s.nodeLastReq[n]; !ok || time.Duration(now-lastReq.time) > radiusTC {
					s.nodeLastReq[n] = reqInfo{pingHash: nil, lookup: lookup, time: now}
				}
			} // else {
			if s.canQueryTopic(n, lookup.topic) {
				hash := query(n, lookup.topic)
				if hash != nil {
					s.addTopicQuery(common.BytesToHash(hash), n, lookup)
				}
			}
			//}
		}
	}
}

func (s *ticketStore) adjustWithTicket(now mclock.AbsTime, targetHash common.Hash, t *ticket) {
	for i, topic := range t.topics {
		if tt, ok := s.radius[topic]; ok {
			tt.adjustWithTicket(now, targetHash, ticketRef{t, i})
		}
	}
}

func (s *ticketStore) addTicket(localTime mclock.AbsTime, pingHash []byte, ticket *ticket) {
	log.Trace("Adding discovery ticket", "node", ticket.node.ID, "serial", ticket.serial)

	lastReq, ok := s.nodeLastReq[ticket.node]
	if !(ok && bytes.Equal(pingHash, lastReq.pingHash)) {
		return
	}
	s.adjustWithTicket(localTime, lastReq.lookup.target, ticket)

	if lastReq.lookup.radiusLookup || s.nodes[ticket.node] != nil {
		return
	}

	topic := lastReq.lookup.topic
	topicIdx := ticket.findIdx(topic)
	if topicIdx == -1 {
		return
	}

	bucket := timeBucket(localTime / mclock.AbsTime(ticketTimeBucketLen))
	if s.lastBucketFetched == 0 || bucket < s.lastBucketFetched {
		s.lastBucketFetched = bucket
	}

	if _, ok := s.tickets[topic]; ok {
		wait := ticket.regTime[topicIdx] - localTime
		rnd := rand.ExpFloat64()
		if rnd > 10 {
			rnd = 10
		}
		if float64(wait) < float64(keepTicketConst)+float64(keepTicketExp)*rnd {
			// use the ticket to register this topic
			//fmt.Println("addTicket", ticket.node.ID[:8], ticket.node.addr().String(), ticket.serial, ticket.pong)
			s.addTicketRef(ticketRef{ticket, topicIdx})
		}
	}

	if ticket.refCnt > 0 {
		s.nextTicketCached = nil
		s.nodes[ticket.node] = ticket
	}
}

func (s *ticketStore) getNodeTicket(node *Node) *ticket {
	if s.nodes[node] == nil {
		log.Trace("Retrieving node ticket", "node", node.ID, "serial", nil)
	} else {
		log.Trace("Retrieving node ticket", "node", node.ID, "serial", s.nodes[node].serial)
	}
	return s.nodes[node]
}

func (s *ticketStore) canQueryTopic(node *Node, topic Topic) bool {
	qq := s.queriesSent[node]
	if qq != nil {
		now := mclock.Now()
		for _, sq := range qq {
			if sq.lookup.topic == topic && sq.sent > now-mclock.AbsTime(topicQueryResend) {
				return false
			}
		}
	}
	return true
}

func (s *ticketStore) addTopicQuery(hash common.Hash, node *Node, lookup lookupInfo) {
	now := mclock.Now()
	qq := s.queriesSent[node]
	if qq == nil {
		qq = make(map[common.Hash]sentQuery)
		s.queriesSent[node] = qq
	}
	qq[hash] = sentQuery{sent: now, lookup: lookup}
	s.cleanupTopicQueries(now)
}

func (s *ticketStore) cleanupTopicQueries(now mclock.AbsTime) {
	if s.nextTopicQueryCleanup > now {
		return
	}
	exp := now - mclock.AbsTime(topicQueryResend)
	for n, qq := range s.queriesSent {
		for h, q := range qq {
			if q.sent < exp {
				delete(qq, h)
			}
		}
		if len(qq) == 0 {
			delete(s.queriesSent, n)
		}
	}
	s.nextTopicQueryCleanup = now + mclock.AbsTime(topicQueryTimeout)
}

func (s *ticketStore) gotTopicNodes(from *Node, hash common.Hash, nodes []rpcNode) (timeout bool) {
	now := mclock.Now()
	//fmt.Println("got", from.addr().String(), hash, len(nodes))
	qq := s.queriesSent[from]
	if qq == nil {
		return true
	}
	q, ok := qq[hash]
	if !ok || now > q.sent+mclock.AbsTime(topicQueryTimeout) {
		return true
	}
	inside := float64(0)
	if len(nodes) > 0 {
		inside = 1
	}
	s.radius[q.lookup.topic].adjust(now, q.lookup.target, from.sha, inside)
	chn := s.searchTopicMap[q.lookup.topic].foundChn
	if chn == nil {
		//fmt.Println("no channel")
		return false
	}
	for _, node := range nodes {
		ip := node.IP
		if ip.IsUnspecified() || ip.IsLoopback() {
			ip = from.IP
		}
		n := NewNode(node.ID, ip, node.UDP, node.TCP)
		select {
		case chn <- n:
		default:
			return false
		}
	}
	return false
}

type topicRadius struct {
	/* topic名称 */
	topic Topic
	/* topic的hash值前缀 */
	topicHashPrefix uint64

	/* 该topic的半径范围，与最小半径，这里主要用于广播时，在一定距离内广播消息，而非全网广播 */
	radius, minRadius uint64

	/* 该里该topic最近的 节点列表 */
	buckets []topicRadiusBucket

	/* 是否可以聚集。。不明白什么意思 */
	converged bool

	/* 在topic半径距离内 查询的次数 */
	radiusLookupCnt int
}

type topicRadiusEvent int

const (
	trOutside topicRadiusEvent = iota
	trInside
	trNoAdjust
	trCount
)

type topicRadiusBucket struct {
	weights    [trCount]float64
	lastTime   mclock.AbsTime
	value      float64
	lookupSent map[common.Hash]mclock.AbsTime
}

func (b *topicRadiusBucket) update(now mclock.AbsTime) {
	if now == b.lastTime {
		return
	}
	exp := math.Exp(-float64(now-b.lastTime) / float64(radiusTC))
	for i, w := range b.weights {
		b.weights[i] = w * exp
	}
	b.lastTime = now

	for target, tm := range b.lookupSent {
		if now-tm > mclock.AbsTime(respTimeout) {
			b.weights[trNoAdjust] += 1
			delete(b.lookupSent, target)
		}
	}
}

func (b *topicRadiusBucket) adjust(now mclock.AbsTime, inside float64) {
	b.update(now)
	if inside <= 0 {
		b.weights[trOutside] += 1
	} else {
		if inside >= 1 {
			b.weights[trInside] += 1
		} else {
			b.weights[trInside] += inside
			b.weights[trOutside] += 1 - inside
		}
	}
}

/**
 * 添加一个topic
 *
 * 添加时，要需要计算topic的广播半径
 */
func newTopicRadius(t Topic) *topicRadius {
	/* 计算该topic的名字的hash值 */
	topicHash := crypto.Keccak256Hash([]byte(t))

	/* 取hash的前8位 */
	topicHashPrefix := binary.BigEndian.Uint64(topicHash[0:8])

	/* 实例化该topic的半径参数 */
	return &topicRadius{
		topic:           t,
		topicHashPrefix: topicHashPrefix,
		radius:          maxRadius,
		minRadius:       maxRadius,
	}
}

func (r *topicRadius) getBucketIdx(addrHash common.Hash) int {
	prefix := binary.BigEndian.Uint64(addrHash[0:8])
	var log2 float64
	if prefix != r.topicHashPrefix {
		log2 = math.Log2(float64(prefix ^ r.topicHashPrefix))
	}
	bucket := int((64 - log2) * radiusBucketsPerBit)
	max := 64*radiusBucketsPerBit - 1
	if bucket > max {
		return max
	}
	if bucket < 0 {
		return 0
	}
	return bucket
}

func (r *topicRadius) targetForBucket(bucket int) common.Hash {
	min := math.Pow(2, 64-float64(bucket+1)/radiusBucketsPerBit)
	max := math.Pow(2, 64-float64(bucket)/radiusBucketsPerBit)
	a := uint64(min)
	b := randUint64n(uint64(max - min))
	xor := a + b
	if xor < a {
		xor = ^uint64(0)
	}
	prefix := r.topicHashPrefix ^ xor
	var target common.Hash
	binary.BigEndian.PutUint64(target[0:8], prefix)
	globalRandRead(target[8:])
	return target
}

// package rand provides a Read function in Go 1.6 and later, but
// we can't use it yet because we still support Go 1.5.
func globalRandRead(b []byte) {
	pos := 0
	val := 0
	for n := 0; n < len(b); n++ {
		if pos == 0 {
			val = rand.Int()
			pos = 7
		}
		b[n] = byte(val)
		val >>= 8
		pos--
	}
}

func (r *topicRadius) isInRadius(addrHash common.Hash) bool {
	nodePrefix := binary.BigEndian.Uint64(addrHash[0:8])
	dist := nodePrefix ^ r.topicHashPrefix
	return dist < r.radius
}

func (r *topicRadius) chooseLookupBucket(a, b int) int {
	if a < 0 {
		a = 0
	}
	if a > b {
		return -1
	}
	c := 0
	for i := a; i <= b; i++ {
		if i >= len(r.buckets) || r.buckets[i].weights[trNoAdjust] < maxNoAdjust {
			c++
		}
	}
	if c == 0 {
		return -1
	}
	rnd := randUint(uint32(c))
	for i := a; i <= b; i++ {
		if i >= len(r.buckets) || r.buckets[i].weights[trNoAdjust] < maxNoAdjust {
			if rnd == 0 {
				return i
			}
			rnd--
		}
	}
	panic(nil) // should never happen
}

func (r *topicRadius) needMoreLookups(a, b int, maxValue float64) bool {
	var max float64
	if a < 0 {
		a = 0
	}
	if b >= len(r.buckets) {
		b = len(r.buckets) - 1
		if r.buckets[b].value > max {
			max = r.buckets[b].value
		}
	}
	if b >= a {
		for i := a; i <= b; i++ {
			if r.buckets[i].value > max {
				max = r.buckets[i].value
			}
		}
	}
	return maxValue-max < minPeakSize
}

func (r *topicRadius) recalcRadius() (radius uint64, radiusLookup int) {
	maxBucket := 0
	maxValue := float64(0)
	now := mclock.Now()
	v := float64(0)
	for i := range r.buckets {
		r.buckets[i].update(now)
		v += r.buckets[i].weights[trOutside] - r.buckets[i].weights[trInside]
		r.buckets[i].value = v
		//fmt.Printf("%v %v | ", v, r.buckets[i].weights[trNoAdjust])
	}
	//fmt.Println()
	slopeCross := -1
	for i, b := range r.buckets {
		v := b.value
		if v < float64(i)*minSlope {
			slopeCross = i
			break
		}
		if v > maxValue {
			maxValue = v
			maxBucket = i + 1
		}
	}

	minRadBucket := len(r.buckets)
	sum := float64(0)
	for minRadBucket > 0 && sum < minRightSum {
		minRadBucket--
		b := r.buckets[minRadBucket]
		sum += b.weights[trInside] + b.weights[trOutside]
	}
	r.minRadius = uint64(math.Pow(2, 64-float64(minRadBucket)/radiusBucketsPerBit))

	lookupLeft := -1
	if r.needMoreLookups(0, maxBucket-lookupWidth-1, maxValue) {
		lookupLeft = r.chooseLookupBucket(maxBucket-lookupWidth, maxBucket-1)
	}
	lookupRight := -1
	if slopeCross != maxBucket && (minRadBucket <= maxBucket || r.needMoreLookups(maxBucket+lookupWidth, len(r.buckets)-1, maxValue)) {
		for len(r.buckets) <= maxBucket+lookupWidth {
			r.buckets = append(r.buckets, topicRadiusBucket{lookupSent: make(map[common.Hash]mclock.AbsTime)})
		}
		lookupRight = r.chooseLookupBucket(maxBucket, maxBucket+lookupWidth-1)
	}
	if lookupLeft == -1 {
		radiusLookup = lookupRight
	} else {
		if lookupRight == -1 {
			radiusLookup = lookupLeft
		} else {
			if randUint(2) == 0 {
				radiusLookup = lookupLeft
			} else {
				radiusLookup = lookupRight
			}
		}
	}

	//fmt.Println("mb", maxBucket, "sc", slopeCross, "mrb", minRadBucket, "ll", lookupLeft, "lr", lookupRight, "mv", maxValue)

	if radiusLookup == -1 {
		// no more radius lookups needed at the moment, return a radius
		r.converged = true
		rad := maxBucket
		if minRadBucket < rad {
			rad = minRadBucket
		}
		radius = ^uint64(0)
		if rad > 0 {
			radius = uint64(math.Pow(2, 64-float64(rad)/radiusBucketsPerBit))
		}
		r.radius = radius
	}

	return
}

func (r *topicRadius) nextTarget(forceRegular bool) lookupInfo {
	if !forceRegular {
		_, radiusLookup := r.recalcRadius()
		if radiusLookup != -1 {
			target := r.targetForBucket(radiusLookup)
			r.buckets[radiusLookup].lookupSent[target] = mclock.Now()
			return lookupInfo{target: target, topic: r.topic, radiusLookup: true}
		}
	}

	radExt := r.radius / 2
	if radExt > maxRadius-r.radius {
		radExt = maxRadius - r.radius
	}
	rnd := randUint64n(r.radius) + randUint64n(2*radExt)
	if rnd > radExt {
		rnd -= radExt
	} else {
		rnd = radExt - rnd
	}

	prefix := r.topicHashPrefix ^ rnd
	var target common.Hash
	binary.BigEndian.PutUint64(target[0:8], prefix)
	globalRandRead(target[8:])
	return lookupInfo{target: target, topic: r.topic, radiusLookup: false}
}

func (r *topicRadius) adjustWithTicket(now mclock.AbsTime, targetHash common.Hash, t ticketRef) {
	wait := t.t.regTime[t.idx] - t.t.issueTime
	inside := float64(wait)/float64(targetWaitTime) - 0.5
	if inside > 1 {
		inside = 1
	}
	if inside < 0 {
		inside = 0
	}
	r.adjust(now, targetHash, t.t.node.sha, inside)
}

func (r *topicRadius) adjust(now mclock.AbsTime, targetHash, addrHash common.Hash, inside float64) {
	bucket := r.getBucketIdx(addrHash)
	//fmt.Println("adjust", bucket, len(r.buckets), inside)
	if bucket >= len(r.buckets) {
		return
	}
	r.buckets[bucket].adjust(now, inside)
	delete(r.buckets[bucket].lookupSent, targetHash)
}
