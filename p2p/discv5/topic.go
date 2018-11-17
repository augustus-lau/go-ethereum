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
	"container/heap"
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/log"
)

const (
	/* 本地最多缓存 的 节点订阅topic的数量 */
	maxEntries = 10000 //最大1w个数量

	/* 每个topic最多可以被 订阅的数量，这决定了广播的性能 */
	maxEntriesPerTopic = 50 //每个topic中最大包含的数量

	fallbackRegistrationExpiry = 1 * time.Hour //注册过期时间
)

// 主题
type Topic string

//如果接收到多个请求时，一个请求就是一个topicEntry
type topicEntry struct {
	topic   Topic          // 主题 字符串
	fifoIdx uint64         // 当节点订阅了多个topic后，该topic的优先级
	node    *Node          // 发布该topic的节点
	expire  mclock.AbsTime // 过期时间
}

/* 这里可以理解为：某个主题 被其他节点订阅的信息  */
type topicInfo struct {
	/* k/v形式    订阅该topic的节点优先级：订阅该topic的节点 */
	/* 这里按照先订阅，后订阅维护顺序，维护本地节点所订阅的所有topic */
	entries            map[uint64]*topicEntry // 那么它的索引就是最小的0，最后订阅的优先级是最后。
	fifoHead, fifoTail uint64                 // 指向entries数组的 头尾指针
	rqItem             *topicRequestQueueItem // 请求的内容实体
	wcl                waitControlLoop
}

// removes tail element from the fifo
// 从所有注册的节点中，删除掉最后一个
func (t *topicInfo) getFifoTail() *topicEntry {

	/* 如果末尾对应的topic 为空 */
	for t.entries[t.fifoTail] == nil {

		/* 我为为什么要+1，因为这里是先进先出的 */
		t.fifoTail++
	}
	tail := t.entries[t.fifoTail]
	t.fifoTail++
	return tail
}

/* 集群中一个节点的信息。比如拿当前节点来说应该包含如下内容 */
type nodeInfo struct {

	/* 每个topic 所对应的 主题内容(包含topic的过期时间，优先级，谁发布的) */
	entries map[Topic]*topicEntry

	lastIssuedTicket, lastUsedTicket uint32 //最新的发布时间，最新的适用某节点的时间
	// you can't register a ticket newer than lastUsedTicket before noRegUntil (absolute time)
	noRegUntil mclock.AbsTime //超时时间
}

/* 一个节点 既能发布主题，也能订阅主题，这里该怎么区分呢？？？？ */
type topicTable struct {
	/* 数据库 */
	db *nodeDB
	/* 自己 */
	self *Node
	/* 没个节点所订阅的主题 */
	nodes map[*Node]*nodeInfo
	/* 统计集群中，所有topic 被订阅的情况 */
	topics map[Topic]*topicInfo

	/* 有多少topic对象 */
	globalEntries uint64

	/* topic被订阅的 数量  */
	requested topicRequestQueue

	/* 全部节点的数量，表示如果有消息，则要发送给全部订阅节点的数量 */
	requestCnt uint64

	/* 最新回收时间 */
	lastGarbageCollection mclock.AbsTime
}

/* 创建一个空的topic表 */
func newTopicTable(db *nodeDB, self *Node) *topicTable {
	if printTestImgLogs {
		fmt.Printf("*N %016x\n", self.sha[:8])
	}

	/* 创建一个topic表 */
	return &topicTable{
		db:     db,
		nodes:  make(map[*Node]*nodeInfo),
		topics: make(map[Topic]*topicInfo),
		self:   self,
	}
}

/* 去订阅topic 主题 */
func (t *topicTable) getOrNewTopic(topic Topic) *topicInfo {

	/* 查看有没有订阅该主题 */
	ti := t.topics[topic]

	//如果topic缓存中没有，则创建从请求的队列中创建一个
	if ti == nil {
		// 该订阅号 对应的推送消息 队列
		rqItem := &topicRequestQueueItem{
			topic:    topic,
			priority: t.requestCnt,
		}

		ti = &topicInfo{
			entries: make(map[uint64]*topicEntry),
			rqItem:  rqItem,
		}
		t.topics[topic] = ti

		//将rqItem放到堆缓存中
		heap.Push(&t.requested, rqItem)
	}
	return ti
}

/* 当前节点取消主题 topic的订阅 */
func (t *topicTable) checkDeleteTopic(topic Topic) {
	ti := t.topics[topic]
	if ti == nil {
		return
	}
	if len(ti.entries) == 0 && ti.wcl.hasMinimumWaitPeriod() {
		delete(t.topics, topic)
		heap.Remove(&t.requested, ti.rqItem.index)
	}
}

/* 获取node节点发布的所有主题 */
func (t *topicTable) getOrNewNode(node *Node) *nodeInfo {

	/* 获取该节点所发布的所有主题 */
	n := t.nodes[node]
	if n == nil {
		//fmt.Printf("newNode %016x %016x\n", t.self.sha[:8], node.sha[:8])
		var issued, used uint32

		//如果db已经连接，则根据nodeId查找 相应的已发布的版本号 和 已经使用的版本号
		if t.db != nil {
			/* 获取该节点最近一次ticket的发布时间，和 最近一次的使用时间 */
			issued, used = t.db.fetchTopicRegTickets(node.ID)
		}

		// 构建nodeInfo,存储该节点中的topic
		n = &nodeInfo{
			entries:          make(map[Topic]*topicEntry),
			lastIssuedTicket: issued,
			lastUsedTicket:   used,
		}
		t.nodes[node] = n
	}
	return n
}

func (t *topicTable) checkDeleteNode(node *Node) {
	if n, ok := t.nodes[node]; ok && len(n.entries) == 0 && n.noRegUntil < mclock.Now() {
		//fmt.Printf("deleteNode %016x %016x\n", t.self.sha[:8], node.sha[:8])
		delete(t.nodes, node)
	}
}

/* 将node的 主题的 发布信息保存到db中 */
/* ticket 其实代表的就是 一种订阅类型的 开始正式可适用的时间。就像入场券一样，订阅类型正式开始使用 */
func (t *topicTable) storeTicketCounters(node *Node) {
	n := t.getOrNewNode(node)

	/* 注册node的所有topic，更新有效期。代表这可以正式使用了 */
	if t.db != nil {
		t.db.updateTopicRegTickets(node.ID, n.lastIssuedTicket, n.lastUsedTicket)
	}
}

/* 从主题表中 获取订阅该topic的 所有节点 */
func (t *topicTable) getEntries(topic Topic) []*Node {
	t.collectGarbage()

	/* 获取该topic 被其他节点订阅的信息 */
	te := t.topics[topic]
	if te == nil {
		return nil
	}

	/* 保存集群中 订阅该主题的 节点*/
	nodes := make([]*Node, len(te.entries))
	i := 0

	/* 提取订阅了该主题的其他节点 */
	for _, e := range te.entries {
		nodes[i] = e.node
		i++
	}
	/* 这个参数好奇怪，查询一次这个接口，就加一次 */
	t.requestCnt++

	/* 更新待发送的消息队列 */
	t.requested.update(te.rqItem, t.requestCnt)
	return nodes
}

/* node节点 订阅topic */
func (t *topicTable) addEntry(node *Node, topic Topic) {

	/* 获取节点node所发布的所有订阅号 */
	n := t.getOrNewNode(node)

	// clear previous entries by the same node
	/* 清空该节点所发布的订阅号的 所有超时时间等，但订阅号不删 */
	for _, e := range n.entries {
		t.deleteEntry(e)
	}
	// 这里有执行一遍，表示创建一个新的。。写的太无语了
	n = t.getOrNewNode(node)

	tm := mclock.Now()

	/* 获取该topic被订阅的 节点 */
	te := t.getOrNewTopic(topic)

	/* 如果满足等于每个topic被订阅的最大值，则删除掉尾部的数据 */
	if len(te.entries) == maxEntriesPerTopic {
		t.deleteEntry(te.getFifoTail())
	}
	/* 如果本地保存的 所有的订阅关系 已经到最大了 */
	if t.globalEntries == maxEntries {
		t.deleteEntry(t.leastRequested()) // not empty, no need to check for nil
	}
	/* 移动指针 */
	fifoIdx := te.fifoHead
	te.fifoHead++

	entry := &topicEntry{
		topic:   topic,                                           //订阅的主题
		fifoIdx: fifoIdx,                                         //上一个被订阅的数据
		node:    node,                                            //订阅者
		expire:  tm + mclock.AbsTime(fallbackRegistrationExpiry), //过期时间 = 当前时间+监听时间
	}
	if printTestImgLogs {
		fmt.Printf("*+ %d %v %016x %016x\n", tm/1000000, topic, t.self.sha[:8], node.sha[:8])
	}
	/* 将索引执行新订阅的 节点数据 */
	te.entries[fifoIdx] = entry
	n.entries[topic] = entry
	t.globalEntries++
	te.wcl.registered(tm)
}

// removes least requested element from the fifo
func (t *topicTable) leastRequested() *topicEntry {
	for t.requested.Len() > 0 && t.topics[t.requested[0].topic] == nil {
		heap.Pop(&t.requested)
	}
	if t.requested.Len() == 0 {
		return nil
	}
	return t.topics[t.requested[0].topic].getFifoTail()
}

// entry should exist
func (t *topicTable) deleteEntry(e *topicEntry) {
	if printTestImgLogs {
		fmt.Printf("*- %d %v %016x %016x\n", mclock.Now()/1000000, e.topic, t.self.sha[:8], e.node.sha[:8])
	}
	ne := t.nodes[e.node].entries
	delete(ne, e.topic)
	if len(ne) == 0 {
		t.checkDeleteNode(e.node)
	}
	te := t.topics[e.topic]
	delete(te.entries, e.fifoIdx)
	if len(te.entries) == 0 {
		t.checkDeleteTopic(e.topic)
	}
	t.globalEntries--
}

// It is assumed that topics and waitPeriods have the same length.
/* 注册该节点发布的主题，返回是否注册成功 */
func (t *topicTable) useTicket(node *Node, serialNo uint32, topics []Topic, idx int, issueTime uint64, waitPeriods []uint32) (registered bool) {
	log.Trace("Using discovery ticket", "serial", serialNo, "topics", topics, "waits", waitPeriods)
	//fmt.Println("useTicket", serialNo, topics, waitPeriods)
	t.collectGarbage()

	n := t.getOrNewNode(node)
	if serialNo < n.lastUsedTicket {
		return false
	}

	tm := mclock.Now()
	if serialNo > n.lastUsedTicket && tm < n.noRegUntil {
		return false
	}

	/* 也就是说 当前时间 >= n.noRegUntil */
	if serialNo != n.lastUsedTicket {
		n.lastUsedTicket = serialNo
		n.noRegUntil = tm + mclock.AbsTime(noRegTimeout())
		t.storeTicketCounters(node)
	}

	currTime := uint64(tm / mclock.AbsTime(time.Second))
	regTime := issueTime + uint64(waitPeriods[idx])
	relTime := int64(currTime - regTime)
	if relTime >= -1 && relTime <= regTimeWindow+1 { // give clients a little security margin on both ends
		if e := n.entries[topics[idx]]; e == nil {
			t.addEntry(node, topics[idx])
		} else {
			// if there is an active entry, don't move to the front of the FIFO but prolong expire time
			e.expire = tm + mclock.AbsTime(fallbackRegistrationExpiry)
		}
		return true
	}

	return false
}

/**
 * 要想将发布的主题 注册，必须要一个门票才能注册，这个门票其实就是一个递增的序列号。
 * 只有拿到这个门票，才能将主题 注册到数据库中。这个方法就是 产生门票的方法。用该门票调用useTicket方法去注册这些主题。之后才能使用
 * @param node   要发布主题的节点
 * @param topics 要发布的主题
 * @ticket  入场券(发布序号或者注册序号)
 */
func (topictab *topicTable) getTicket(node *Node, topics []Topic) *ticket {

	/* 回收过期的主题 */
	topictab.collectGarbage()

	now := mclock.Now()
	//获取或者创建一个新的节点
	n := topictab.getOrNewNode(node)

	/* topic表中，没次发布都会产生一个自增长的序号。代表的是主题发布的次数 */
	n.lastIssuedTicket++

	/* 发布入场券(也就是更新一次node节点所发布的所有订阅号的有效期) */
	topictab.storeTicketCounters(node)

	t := &ticket{
		issueTime: now,                                 //节点的发布时间(数据库到内存)
		topics:    topics,                              //节点所订阅的所有topic
		serial:    n.lastIssuedTicket,                  //该节点第几次从数据库到内存发布
		regTime:   make([]mclock.AbsTime, len(topics)), //所有主题的注册时间
	}

	//遍历该节点订阅的topic
	for i, topic := range topics {
		var waitPeriod time.Duration //订阅的等待周期
		if topic := topictab.topics[topic]; topic != nil {
			waitPeriod = topic.wcl.waitPeriod //该订阅消息的 每次轮询的周期
		} else {
			waitPeriod = minWaitPeriod //在本地中没有找到该订阅消息的刷新周期，那么设置为最小的刷新周期
		}

		// 订阅消息的 注册时间就是 当前时间+刷新周期
		t.regTime[i] = now + mclock.AbsTime(waitPeriod)
	}
	return t
}

const gcInterval = time.Minute

func (t *topicTable) collectGarbage() {
	tm := mclock.Now()
	if time.Duration(tm-t.lastGarbageCollection) < gcInterval {
		return
	}
	t.lastGarbageCollection = tm

	for node, n := range t.nodes {
		for _, e := range n.entries {
			if e.expire <= tm {
				t.deleteEntry(e)
			}
		}

		t.checkDeleteNode(node)
	}

	for topic := range t.topics {
		t.checkDeleteTopic(topic)
	}
}

const (
	minWaitPeriod   = time.Minute //订阅消息是1分钟刷新一次
	regTimeWindow   = 10          // seconds
	avgnoRegTimeout = time.Minute * 10
	// target average interval between two incoming ad requests
	wcTargetRegInterval = time.Minute * 10 / maxEntriesPerTopic
	//
	wcTimeConst = time.Minute * 10
)

// initialization is not required, will set to minWaitPeriod at first registration
type waitControlLoop struct {
	lastIncoming mclock.AbsTime
	waitPeriod   time.Duration
}

func (w *waitControlLoop) registered(tm mclock.AbsTime) {
	w.waitPeriod = w.nextWaitPeriod(tm)
	w.lastIncoming = tm
}

func (w *waitControlLoop) nextWaitPeriod(tm mclock.AbsTime) time.Duration {
	period := tm - w.lastIncoming
	wp := time.Duration(float64(w.waitPeriod) * math.Exp((float64(wcTargetRegInterval)-float64(period))/float64(wcTimeConst)))
	if wp < minWaitPeriod {
		wp = minWaitPeriod
	}
	return wp
}

func (w *waitControlLoop) hasMinimumWaitPeriod() bool {
	return w.nextWaitPeriod(mclock.Now()) == minWaitPeriod
}

func noRegTimeout() time.Duration {
	e := rand.ExpFloat64()
	if e > 100 {
		e = 100
	}
	return time.Duration(float64(avgnoRegTimeout) * e)
}

type topicRequestQueueItem struct {
	topic    Topic
	priority uint64
	index    int
}

// A topicRequestQueue implements heap.Interface and holds topicRequestQueueItems.
type topicRequestQueue []*topicRequestQueueItem

func (tq topicRequestQueue) Len() int { return len(tq) }

func (tq topicRequestQueue) Less(i, j int) bool {
	return tq[i].priority < tq[j].priority
}

func (tq topicRequestQueue) Swap(i, j int) {
	tq[i], tq[j] = tq[j], tq[i]
	tq[i].index = i
	tq[j].index = j
}

func (tq *topicRequestQueue) Push(x interface{}) {
	n := len(*tq)
	item := x.(*topicRequestQueueItem)
	item.index = n
	*tq = append(*tq, item)
}

func (tq *topicRequestQueue) Pop() interface{} {
	old := *tq
	n := len(old)
	item := old[n-1]
	item.index = -1
	*tq = old[0 : n-1]
	return item
}

func (tq *topicRequestQueue) update(item *topicRequestQueueItem, priority uint64) {
	item.priority = priority
	heap.Fix(tq, item.index)
}
