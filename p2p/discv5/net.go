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
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/netutil"
	"github.com/ethereum/go-ethereum/rlp"
)

var (
	//无效的状态
	errInvalidEvent = errors.New("invalid in current state")

	//没有正在等待的查询
	errNoQuery = errors.New("no pending query")
)

const (
	//自动刷新时间间隔
	autoRefreshInterval = 1 * time.Hour
	//k-桶刷新间隔
	bucketRefreshInterval = 1 * time.Minute
	//种子数量--一次从db中加载的种子的数量
	seedCount = 30
	//种子节点的最大生命周期
	seedMaxAge = 5 * 24 * time.Hour
	//端口不能小于1024
	lowPort = 1024
)

// 测试topic
const testTopic = "foo"

const (
	printTestImgLogs = false
)

// 网络层，管理路由表 和协议的交互
// Network manages the table and all protocol interaction.
type Network struct {

	/* 其他层或者公用的组件包括db层，udp连接层等 */
	db          *nodeDB   // database of known nodes
	conn        transport // udp连接层
	netrestrict *netutil.Netlist

	/* 各种交互通道 */

	// 网络层关闭信号通道
	closed chan struct{} // closed when loop is done

	// 待关闭的request的信号通道
	closeReq chan struct{} // 'request to close'
	// 刷新节点的信号通道
	refreshReq chan []*Node // lookups ask for refresh on this channel

	/* 等待刷新的结果的通道，这里主要是block启动刷新任务，保证同时只能有一个刷新任务 */
	refreshResp chan (<-chan struct{}) // ...and get the channel to block on from this one

	// 接收到的请求放入到该通道
	read chan ingressPacket // ingress packets arrive here

	// 超时的信号量通道
	timeout chan timeoutEvent

	// 节点查询信号量通道
	queryReq chan *findnodeQuery // lookups submit findnode queries on this channel

	/* 路由表的操作请求，将所有对路与表操作的请求都放置到一个通道 */
	// 对路由表操作的请求 信号量通道
	tableOpReq chan func()

	// 路由表 对请求相应的 信号量通道
	tableOpResp chan struct{}

	// topic注册请求 通道
	topicRegisterReq chan topicRegisterReq
	// topic检索请求 同奥
	topicSearchReq chan topicSearchReq

	/* 网络层中的存储对象，loop方法要更新的对象 */
	// State of the main loop.
	tab         *Table
	topictab    *topicTable
	ticketStore *ticketStore
	nursery     []*Node
	// 保存未连接的节点
	nodes         map[NodeID]*Node // tracks active nodes with state != known
	timeoutTimers map[timeoutEvent]*time.Timer

	/* 需要重新验证的队列 */
	// Revalidation queues.
	// Nodes put on these queues will be pinged eventually.
	slowRevalidateQueue []*Node
	fastRevalidateQueue []*Node

	/* 数据包缓冲区 */
	// Buffers for state transition.
	sendBuf []*ingressPacket
}

/* 传输层构建 */
// transport is implemented by the UDP transport.
// it is an interface so we can test without opening lots of UDP
// sockets and without generating a private key.
type transport interface {
	sendPing(remote *Node, remoteAddr *net.UDPAddr, topics []Topic) (hash []byte)
	sendNeighbours(remote *Node, nodes []*Node)
	sendFindnodeHash(remote *Node, target common.Hash)
	sendTopicRegister(remote *Node, topics []Topic, topicIdx int, pong []byte)
	sendTopicNodes(remote *Node, queryHash common.Hash, nodes []*Node)

	send(remote *Node, ptype nodeEvent, p interface{}) (hash []byte)

	localAddr() *net.UDPAddr
	Close()
}

type findnodeQuery struct {
	remote   *Node
	target   common.Hash
	reply    chan<- []*Node
	nresults int // counter for received nodes
}

type topicRegisterReq struct {
	add   bool
	topic Topic
}

type topicSearchReq struct {
	topic  Topic
	found  chan<- *Node
	lookup chan<- bool
	delay  time.Duration
}

type topicSearchResult struct {
	target lookupInfo
	nodes  []*Node
}

type timeoutEvent struct {
	ev   nodeEvent
	node *Node
}

func newNetwork(conn transport, ourPubkey ecdsa.PublicKey, dbPath string, netrestrict *netutil.Netlist) (*Network, error) {
	ourID := PubkeyID(&ourPubkey)

	//db
	var db *nodeDB
	if dbPath != "<no database>" {
		var err error
		if db, err = newNodeDB(dbPath, Version, ourID); err != nil {
			return nil, err
		}
	}

	//初始化路由表
	tab := newTable(ourID, conn.localAddr())

	//初始化网络层
	net := &Network{
		db:          db,
		conn:        conn,
		netrestrict: netrestrict,
		tab:         tab,                         //路由表
		topictab:    newTopicTable(db, tab.self), //订阅信息表
		ticketStore: newTicketStore(),            //订阅的topic的缓存结构

		/* 流程图已画 */
		refreshReq:  make(chan []*Node),           //刷新请求通道--主要用于刷新路由表中的node节点。当节点发生变化后触发
		refreshResp: make(chan (<-chan struct{})), //刷新相应通道-- 当触发刷新路由表中node节点后，将刷新的结果返回到该通道中。标识是否刷新成功

		closed:   make(chan struct{}), //关闭net信号量通道
		closeReq: make(chan struct{}), //关闭请求通道

		read:             make(chan ingressPacket, 100),      //读取udp数据通道
		timeout:          make(chan timeoutEvent),            //超时通道
		timeoutTimers:    make(map[timeoutEvent]*time.Timer), //调度器map
		tableOpReq:       make(chan func()),                  //请求路由表通道 -- 主要与table交互
		tableOpResp:      make(chan struct{}),                //相应对路由表的请求通道
		queryReq:         make(chan *findnodeQuery),          //查询请求通道
		topicRegisterReq: make(chan topicRegisterReq),        //订阅时间的注册通道
		topicSearchReq:   make(chan topicSearchReq),          //请求订阅通道
		nodes:            make(map[NodeID]*Node),             //所有的本地保存的节点的map
	}
	go net.loop()
	return net, nil
}

// Close terminates the network listener and flushes the node database.
func (net *Network) Close() {
	net.conn.Close()
	select {
	case <-net.closed:
	case net.closeReq <- struct{}{}:
		<-net.closed
	}
}

// Self returns the local node.
// The returned node should not be modified by the caller.
func (net *Network) Self() *Node {
	return net.tab.self
}

// ReadRandomNodes fills the given slice with random nodes from the
// table. It will not write the same node more than once. The nodes in
// the slice are copies and can be modified by the caller.
func (net *Network) ReadRandomNodes(buf []*Node) (n int) {
	net.reqTableOp(func() { n = net.tab.readRandomNodes(buf) })
	return n
}

// 加载 守护节点。 这是当前节点可以连接入网络的保障。   当当前节点的数据库中没有相应的种子节点时，可以依赖守护节点连接入网络中
// SetFallbackNodes sets the initial points of contact. These nodes
// are used to connect to the network if the table is empty and there
// are no known nodes in the database.
func (net *Network) SetFallbackNodes(nodes []*Node) error {
	nursery := make([]*Node, 0, len(nodes))
	for _, n := range nodes {
		if err := n.validateComplete(); err != nil {
			return fmt.Errorf("bad bootstrap/fallback node %q (%v)", n, err)
		}
		// Recompute cpy.sha because the node might not have been
		// created by NewNode or ParseNode.
		cpy := *n
		cpy.sha = crypto.Keccak256Hash(n.ID[:])
		nursery = append(nursery, &cpy)
	}
	net.reqRefresh(nursery)
	return nil
}

// Resolve searches for a specific node with the given ID.
// It returns nil if the node could not be found.
func (net *Network) Resolve(targetID NodeID) *Node {
	result := net.lookup(crypto.Keccak256Hash(targetID[:]), true)
	for _, n := range result {
		if n.ID == targetID {
			return n
		}
	}
	return nil
}

// Lookup performs a network search for nodes close
// to the given target. It approaches the target by querying
// nodes that are closer to it on each iteration.
// The given target does not need to be an actual node
// identifier.
//
// The local node may be included in the result.
func (net *Network) Lookup(targetID NodeID) []*Node {
	return net.lookup(crypto.Keccak256Hash(targetID[:]), false)
}

/**
 * 从全网中去查找target的 n个邻居节点。这里优先在本地查找，其次是从远程节点去查找。
 * 当stopOnMatch = true时，其实代表的就是 从全网中去查找一个 hash值等于target的节点，找到就返回
 * 当stopOnMatch =false时，代表的是 从全网中去查找n个 与hash值最近就节点列表。
 * @param target 查找的目标节点
 * @param stopOnMatch  如果找到的邻居节点中包含了target自己，则停止查找.决定是是否在 全网中去查找
 * @return 返回找到的节点列表
 *
 */
func (net *Network) lookup(target common.Hash, stopOnMatch bool) []*Node {
	var (
		asked          = make(map[NodeID]bool) //正在请求的节点缓存,尚未回复的
		seen           = make(map[NodeID]bool)
		reply          = make(chan []*Node, alpha)
		result         = nodesByDistance{target: target} //创建一个距离结果接对象，这里的目标对象是自己
		pendingQueries = 0                               //正在请求的节点数
	)
	// Get initial answers from the local node.
	/* 首先讲当前节点放入？ 这里为什么呢？因为必须要保证其中至少有一个节点 */
	result.push(net.tab.self, bucketSize)

	//无限循环
	for {

		/* 这里可以看到，如果不将本地节点放入, 那么result就是空的，下面的循环将不会执行 */
		// Ask the α closest nodes that we haven't asked yet.
		// 请求alpha个最近的 尚未请求过的节点
		for i := 0; i < len(result.entries) && pendingQueries < alpha; i++ {

			//entries数组中，是按照远近来排序的，索引小距离近
			n := result.entries[i]

			/* 是否之前已经从该节点上查找过了 */
			if !asked[n.ID] {
				asked[n.ID] = true
				pendingQueries++

				/* 从节点n中，去查询 target节点的k个邻居节点，并将结果放入到reply中 */
				/* 这里如果n是本地节点，那么就从本地查询。 */
				net.reqQueryFindnode(n, target, reply)
			}
		}

		/* 知道遍历了所有的节点 终止内部循环 */
		if pendingQueries == 0 {
			// We have asked all closest nodes, stop the search.
			break
		}
		// Wait for the next reply.
		select {
		//如果请求的回复到达
		case nodes := <-reply:
			/* 遍历已经找到的所有target的邻居节点 */
			for _, n := range nodes {

				/* 这个邻居节点之前没有被发现过,其实就是去重 */
				if n != nil && !seen[n.ID] {
					seen[n.ID] = true

					/* 将结果放入到result中，然后又继续执行最外层的for循环,直到填充满result未知 */
					result.push(n, bucketSize)
					/* 发现找到的结果中包含了 目标节点时。根据stopOnMatch来决定是否返回 */
					if stopOnMatch && n.sha == target {
						return result.entries
					}
				}
			}
			pendingQueries--
		/*如果 查找的时间已经超时，则停止*/
		case <-time.After(respTimeout):
			// forget all pending requests, start new ones
			pendingQueries = 0
			reply = make(chan []*Node, alpha)
		}
	}
	return result.entries
}

func (net *Network) RegisterTopic(topic Topic, stop <-chan struct{}) {
	select {
	case net.topicRegisterReq <- topicRegisterReq{true, topic}:
	case <-net.closed:
		return
	}
	select {
	case <-net.closed:
	case <-stop:
		select {
		case net.topicRegisterReq <- topicRegisterReq{false, topic}:
		case <-net.closed:
		}
	}
}

func (net *Network) SearchTopic(topic Topic, setPeriod <-chan time.Duration, found chan<- *Node, lookup chan<- bool) {
	for {
		select {
		case <-net.closed:
			return
		case delay, ok := <-setPeriod:
			select {
			case net.topicSearchReq <- topicSearchReq{topic: topic, found: found, lookup: lookup, delay: delay}:
			case <-net.closed:
				return
			}
			if !ok {
				return
			}
		}
	}
}

//按照守护节点来发送刷新请求
func (net *Network) reqRefresh(nursery []*Node) <-chan struct{} {
	select {
	case net.refreshReq <- nursery:
		return <-net.refreshResp
	case <-net.closed:
		return net.closed
	}
}

/**
 * @param n  请求的目的地
 * @param target 发送来源
 * @param reply是一个通道 将结果写入该通道中
 *
 *
 */
func (net *Network) reqQueryFindnode(n *Node, target common.Hash, reply chan []*Node) bool {
	q := &findnodeQuery{remote: n, target: target, reply: reply}
	select {
	//将请求写入到queryReq通道中，等待发送
	case net.queryReq <- q:
		return true
	case <-net.closed:
		return false
	}
}

func (net *Network) reqReadPacket(pkt ingressPacket) {
	select {
	case net.read <- pkt:
	case <-net.closed:
	}
}

func (net *Network) reqTableOp(f func()) (called bool) {
	select {
	case net.tableOpReq <- f:
		<-net.tableOpResp
		return true
	case <-net.closed:
		return false
	}
}

// TODO: external address handling.

type topicSearchInfo struct {
	lookupChn chan<- bool
	period    time.Duration
}

const maxSearchCount = 5

/* 网络层开始的方法 start net */
func (net *Network) loop() {
	var (
		/* ticker监听器，没到时间后自动执行，不需要其他操作 */
		refreshTimer = time.NewTicker(autoRefreshInterval)
		/* timer监听器，如果超时未完成，需要重新reset才能继续执行 */
		bucketRefreshTimer = time.NewTimer(bucketRefreshInterval)
		/* 刷新完成的信号量 */
		refreshDone chan struct{} // closed when the 'refresh' lookup has ended
	)

	// Tracking the next ticket to register.
	var (
		/* 保存下一个topic 的索引未知 */
		nextTicket *ticketRef
		/* 下次注册的监听器 */
		nextRegisterTimer *time.Timer
		/* 下次注册的时间 */
		nextRegisterTime <-chan time.Time
	)

	/* 如果注册监听器不为空，则初始化时，先将监听器关闭，防止启动两个监听器 */
	defer func() {
		if nextRegisterTimer != nil {
			nextRegisterTimer.Stop()
		}
	}()

	/* 重置下一个ticket，找到下一个ticket，并将监听器绑定到其上面 */
	resetNextTicket := func() {
		ticket, timeout := net.ticketStore.nextFilteredTicket()
		if nextTicket != ticket {
			nextTicket = ticket
			if nextRegisterTimer != nil {
				nextRegisterTimer.Stop()
				nextRegisterTime = nil
			}
			if ticket != nil {
				nextRegisterTimer = time.NewTimer(timeout)
				nextRegisterTime = nextRegisterTimer.C
			}
		}
	}

	// Tracking registration and search lookups.
	var (
		topicRegisterLookupTarget lookupInfo
		topicRegisterLookupDone   chan []*Node
		topicRegisterLookupTick   = time.NewTimer(0)

		/* 全网中查找topic的请求列表 */
		searchReqWhenRefreshDone []topicSearchReq
		/* 每个topic请求的的 周期，也就是每个topic多久刷新一次，之所以用map,保证了每个topic在全网中只查询一次 */
		searchInfo = make(map[Topic]topicSearchInfo)

		/* 这个参数决定了再一次topic刷新周期内，最多查找几次 */
		activeSearchCount int
	)
	topicSearchLookupDone := make(chan topicSearchResult, 100)
	topicSearch := make(chan Topic, 100)
	<-topicRegisterLookupTick.C

	statsDump := time.NewTicker(10 * time.Second)

loop:
	for {
		resetNextTicket()

		select {
		case <-net.closeReq:
			log.Trace("<-net.closeReq")
			break loop

		// 处理transport层传递进来的udp读取到的数据
		// Ingress packet handling.
		case pkt := <-net.read:
			//fmt.Println("read", pkt.ev)
			log.Trace("<-net.read")

			/* 从udp网络层接受到的 已经解码的数据包 */
			n := net.internNode(&pkt)

			// 获取到该节点当前的状态
			prestate := n.state

			// 默认 执行成功
			status := "ok"

			if err := net.handle(n, pkt.ev, &pkt); err != nil {
				status = err.Error()
			}
			log.Trace("", "msg", log.Lazy{Fn: func() string {
				return fmt.Sprintf("<<< (%d) %v from %x@%v: %v -> %v (%v)",
					net.tab.count, pkt.ev, pkt.remoteID[:8], pkt.remoteAddr, prestate, n.state, status)
			}})
			// TODO: persist state if n.state goes >= known, delete if it goes <= known

		// State transition timeouts.
		case timeout := <-net.timeout: //将通道中某节点超时的消息拿出来
			log.Trace("<-net.timeout")
			if net.timeoutTimers[timeout] == nil {
				// Stale timer (was aborted).
				continue
			}
			delete(net.timeoutTimers, timeout)

			//如果超时了，先校验该节点的状态
			prestate := timeout.node.state
			status := "ok"
			if err := net.handle(timeout.node, timeout.ev, nil); err != nil {
				status = err.Error()
			}
			log.Trace("", "msg", log.Lazy{Fn: func() string {
				return fmt.Sprintf("--- (%d) %v for %x@%v: %v -> %v (%v)",
					net.tab.count, timeout.ev, timeout.node.ID[:8], timeout.node.addr(), prestate, timeout.node.state, status)
			}})

		// Querying.
		case q := <-net.queryReq:
			log.Trace("<-net.queryReq")
			if !q.start(net) {
				q.remote.deferQuery(q)
			}

		// Interacting with the table.
		case f := <-net.tableOpReq:
			log.Trace("<-net.tableOpReq")
			f()
			net.tableOpResp <- struct{}{}

		// Topic registration stuff.
		/* topic的注册 */
		case req := <-net.topicRegisterReq:
			log.Trace("<-net.topicRegisterReq")
			if !req.add {
				net.ticketStore.removeRegisterTopic(req.topic)
				continue
			}
			net.ticketStore.addTopic(req.topic, true)
			// If we're currently waiting idle (nothing to look up), give the ticket store a
			// chance to start it sooner. This should speed up convergence of the radius
			// determination for new topics.
			// if topicRegisterLookupDone == nil {
			if topicRegisterLookupTarget.target == (common.Hash{}) {
				log.Trace("topicRegisterLookupTarget == null")
				if topicRegisterLookupTick.Stop() {
					<-topicRegisterLookupTick.C
				}
				target, delay := net.ticketStore.nextRegisterLookup()
				topicRegisterLookupTarget = target
				topicRegisterLookupTick.Reset(delay)
			}

		case nodes := <-topicRegisterLookupDone:
			log.Trace("<-topicRegisterLookupDone")
			net.ticketStore.registerLookupDone(topicRegisterLookupTarget, nodes, func(n *Node) []byte {
				net.ping(n, n.addr())
				return n.pingEcho
			})
			target, delay := net.ticketStore.nextRegisterLookup()
			topicRegisterLookupTarget = target
			topicRegisterLookupTick.Reset(delay)
			topicRegisterLookupDone = nil

		case <-topicRegisterLookupTick.C:
			log.Trace("<-topicRegisterLookupTick")
			if (topicRegisterLookupTarget.target == common.Hash{}) {
				target, delay := net.ticketStore.nextRegisterLookup()
				topicRegisterLookupTarget = target
				topicRegisterLookupTick.Reset(delay)
				topicRegisterLookupDone = nil
			} else {
				topicRegisterLookupDone = make(chan []*Node)
				target := topicRegisterLookupTarget.target
				go func() { topicRegisterLookupDone <- net.lookup(target, false) }()
			}

		case <-nextRegisterTime:
			log.Trace("<-nextRegisterTime")
			net.ticketStore.ticketRegistered(*nextTicket)
			//fmt.Println("sendTopicRegister", nextTicket.t.node.addr().String(), nextTicket.t.topics, nextTicket.idx, nextTicket.t.pong)
			net.conn.sendTopicRegister(nextTicket.t.node, nextTicket.t.topics, nextTicket.idx, nextTicket.t.pong)

		/* 查询topic 信息的请求 */
		case req := <-net.topicSearchReq:

			/* 必须等待路由表刷新完成后才可以开始 */
			if refreshDone == nil {
				log.Trace("<-net.topicSearchReq")

				/* 找到对该topic查询的 超时信息 */
				info, ok := searchInfo[req.topic]

				/* 如果存在 */
				if ok {
					/* 如果刷新topic刷新周期是0，则删除，代表刷新太快 */
					if req.delay == time.Duration(0) {
						delete(searchInfo, req.topic)
						net.ticketStore.removeSearchTopic(req.topic)
					} else {

						/* 更新该topic的刷新周期 */
						info.period = req.delay
						searchInfo[req.topic] = info
					}
					continue
				}
				/* 如果topic设置了刷新周期 */
				if req.delay != time.Duration(0) {
					var info topicSearchInfo
					info.period = req.delay
					info.lookupChn = req.lookup
					searchInfo[req.topic] = info

					/* 暂存该topic与其时间(入场券) */
					net.ticketStore.addSearchTopic(req.topic, req.found)

					/* 发送请求， */
					topicSearch <- req.topic
				}
			} else {
				searchReqWhenRefreshDone = append(searchReqWhenRefreshDone, req)
			}

		/* 查找topic的通道 */
		case topic := <-topicSearch:

			/* 记录 全网一共进行了几次 topic查找 */
			if activeSearchCount < maxSearchCount {
				activeSearchCount++

				/* 找到该topic主题 是由哪个节点发布的 */
				target := net.ticketStore.nextSearchLookup(topic)

				/* 启动线程 */
				go func() {
					/* 从全网中查询离target最近的k个节点 */
					nodes := net.lookup(target.target, false)

					/*  */
					topicSearchLookupDone <- topicSearchResult{target: target, nodes: nodes}
				}()
			}

			period := searchInfo[topic].period
			/* 如果查找周期不为0，则每隔period就在全网查找一次该主题 */
			if period != time.Duration(0) {
				go func() {
					time.Sleep(period)
					topicSearch <- topic
				}()
			}

		/* 当在全网查找到对应的topic时 */
		case res := <-topicSearchLookupDone:

			/* 将查找次数减一，所以这个参数决定了再一次topic刷新周期内，最多查找几次 */
			activeSearchCount--

			if lookupChn := searchInfo[res.target.topic].lookupChn; lookupChn != nil {
				lookupChn <- net.ticketStore.radius[res.target.topic].converged
			}
			net.ticketStore.searchLookupDone(res.target, res.nodes, func(n *Node, topic Topic) []byte {
				if n.state != nil && n.state.canQuery {
					return net.conn.send(n, topicQueryPacket, topicQuery{Topic: topic}) // TODO: set expiration
				} else {
					if n.state == unknown {
						net.ping(n, n.addr())
					}
					return nil
				}
			})

		case <-statsDump.C:
			log.Trace("<-statsDump.C")
			/*r, ok := net.ticketStore.radius[testTopic]
			if !ok {
				fmt.Printf("(%x) no radius @ %v\n", net.tab.self.ID[:8], time.Now())
			} else {
				topics := len(net.ticketStore.tickets)
				tickets := len(net.ticketStore.nodes)
				rad := r.radius / (maxRadius/10000+1)
				fmt.Printf("(%x) topics:%d radius:%d tickets:%d @ %v\n", net.tab.self.ID[:8], topics, rad, tickets, time.Now())
			}*/

			tm := mclock.Now()
			for topic, r := range net.ticketStore.radius {
				if printTestImgLogs {
					rad := r.radius / (maxRadius/1000000 + 1)
					minrad := r.minRadius / (maxRadius/1000000 + 1)
					fmt.Printf("*R %d %v %016x %v\n", tm/1000000, topic, net.tab.self.sha[:8], rad)
					fmt.Printf("*MR %d %v %016x %v\n", tm/1000000, topic, net.tab.self.sha[:8], minrad)
				}
			}
			for topic, t := range net.topictab.topics {
				wp := t.wcl.nextWaitPeriod(tm)
				if printTestImgLogs {
					fmt.Printf("*W %d %v %016x %d\n", tm/1000000, topic, net.tab.self.sha[:8], wp/1000000)
				}
			}

		/* 先看这里，刷新监听器触发刷新 */
		// Periodic / lookup-initiated bucket refresh.
		case <-refreshTimer.C:
			log.Trace("<-refreshTimer.C")
			// TODO: ideally we would start the refresh timer after
			// fallback nodes have been set for the first time.
			if refreshDone == nil {
				refreshDone = make(chan struct{})
				net.refresh(refreshDone)
			}
		case <-bucketRefreshTimer.C:
			target := net.tab.chooseBucketRefreshTarget()
			go func() {
				net.lookup(target, false)
				bucketRefreshTimer.Reset(bucketRefreshInterval)
			}()

			/* 根据通道中的节点数据，刷新table中的节点状态 */
		case newNursery := <-net.refreshReq:
			log.Trace("<-net.refreshReq")
			if newNursery != nil {
				net.nursery = newNursery
			}

			/* 如果没有正在刷新的任务 */
			if refreshDone == nil {

				/* 构造一个对象，保存刷新的结果 */
				refreshDone = make(chan struct{})
				net.refresh(refreshDone)
			}

			/* 如果已经存在一个刷新任务，等待刷新完成后 返回刷新的停止信号量  */
			net.refreshResp <- refreshDone
		/* 当lookup刷新完成后 */
		case <-refreshDone:
			log.Trace("<-net.refreshDone", "table size", net.tab.count)
			if net.tab.count != 0 {
				refreshDone = nil

				/* 如果种子刷新成功了，则开始在全网中查找所有topic的信息 */
				list := searchReqWhenRefreshDone
				searchReqWhenRefreshDone = nil

				/* 起线程 查询所有的topic */
				go func() {
					for _, req := range list {
						net.topicSearchReq <- req
					}
				}()
				/* 如果刷新完成后，发现路由表中没有发现任何节点，这时要再次触发刷新 */
			} else {
				refreshDone = make(chan struct{})
				net.refresh(refreshDone)
			}
		}
	}

	/* 如果路由表中没有 能加载到任何种子节点，代表本机无法连接到网络中，则停止本机服务 */
	log.Trace("loop stopped")

	log.Debug(fmt.Sprintf("shutting down"))
	if net.conn != nil {
		net.conn.Close()
	}
	if refreshDone != nil {
		// TODO: wait for pending refresh.
		//<-refreshResults
	}
	// Cancel all pending timeouts.
	for _, timer := range net.timeoutTimers {
		timer.Stop()
	}
	if net.db != nil {
		net.db.close()
	}
	close(net.closed)
}

// Everything below runs on the Network.loop goroutine
// and can modify Node, Table and Network at any time without locking.

/* 当刷新通道中接受到数据时，这时就要刷新相应 */
func (net *Network) refresh(done chan<- struct{}) {
	var seeds []*Node

	//从db中拉取种子节点
	if net.db != nil {
		seeds = net.db.querySeeds(seedCount, seedMaxAge)
	}

	//如果没有拉取到--则守护节点就是种子节点
	if len(seeds) == 0 {
		seeds = net.nursery
	}

	if len(seeds) == 0 {
		log.Trace("no seed nodes found")
		close(done)
		return
	}

	//遍历种子节点
	for _, n := range seeds {
		log.Debug("", "msg", log.Lazy{Fn: func() string {
			var age string
			if net.db != nil {

				//找到该节点 最新的一个相应时的状态-如果没有 则设置为unknown
				age = time.Since(net.db.lastPong(n.ID)).String()
			} else {
				age = "unknown"
			}
			return fmt.Sprintf("seed node (age %s): %v", age, n)
		}})

		//保存到network的内存中map中
		n = net.internNodeFromDB(n)
		//如果加载的种子节点是 unknown状态---则初始化时要先设置为verifyinit状态，标识该节点待验证。
		if n.state == unknown {
			/* 将节点的状态 从 unknown 流转到 verifyinit状态 */
			net.transition(n, verifyinit)
		}
		// Force-add the seed node so Lookup does something.
		// It will be deleted again if verification fails.

		//添加到--路由表中
		net.tab.add(n)
	}

	// Start self lookup to fill up the buckets.
	go func() {

		/* 这里的lookup方法感觉没有意义啊，这里从全网去查询了一次当前节点的n个最近节点。但是查找的结果并没有保存，只是空执行了一次 */
		/* 这里 难道只是为了启动前测试网络么 。。 蛋疼 */
		net.Lookup(net.tab.self.ID)
		close(done) //处理完毕后 关闭done通道
	}()
}

// Node Interning.
/* 将生成对应的节点，并且标记为unknown */
func (net *Network) internNode(pkt *ingressPacket) *Node {

	/* 从内存中找到 remote节点，并返回 */
	if n := net.nodes[pkt.remoteID]; n != nil {
		n.IP = pkt.remoteAddr.IP
		n.UDP = uint16(pkt.remoteAddr.Port)
		n.TCP = uint16(pkt.remoteAddr.Port)
		return n
	}

	/* 如果不在内存中，则将其 保存到内存中 */
	n := NewNode(pkt.remoteID, pkt.remoteAddr.IP, uint16(pkt.remoteAddr.Port), uint16(pkt.remoteAddr.Port))
	/* 当接收到remote的数据包时，默认该remote为 'unknown' 状态 */
	n.state = unknown
	net.nodes[pkt.remoteID] = n
	return n
}

//
func (net *Network) internNodeFromDB(dbn *Node) *Node {
	if n := net.nodes[dbn.ID]; n != nil {
		return n
	}
	n := NewNode(dbn.ID, dbn.IP, dbn.UDP, dbn.TCP)
	n.state = unknown
	net.nodes[n.ID] = n
	return n
}

//从当前节点中查找 请求过来让查找的邻居节点
func (net *Network) internNodeFromNeighbours(sender *net.UDPAddr, rn rpcNode) (n *Node, err error) {
	if rn.ID == net.tab.self.ID {
		return nil, errors.New("is self")
	}
	if rn.UDP <= lowPort {
		return nil, errors.New("low port")
	}

	//首先在缓存中查找该节点
	n = net.nodes[rn.ID]
	if n == nil {
		// We haven't seen this node before.
		// 如果内存中没找到，构造一个新节点
		n, err = nodeFromRPC(sender, rn)

		//判断黑名单中是否存在
		if net.netrestrict != nil && !net.netrestrict.Contains(n.IP) {
			return n, errors.New("not contained in netrestrict whitelist")
		}

		//如果都没有，则更新该节点的状态为unknown
		if err == nil {
			n.state = unknown
			net.nodes[n.ID] = n
		}
		return n, err //返回该节点(此时未连接)
	}
	//如果缓存中存在，校验该节点的rpc端口是否一致
	if !n.IP.Equal(rn.IP) || n.UDP != rn.UDP || n.TCP != rn.TCP {
		if n.state == known {
			// reject address change if node is known by us
			err = fmt.Errorf("metadata mismatch: got %v, want %v", rn, n)
		} else {
			//未联通则更新该节点的
			// accept otherwise; this will be handled nicer with signed ENRs
			n.IP = rn.IP
			n.UDP = rn.UDP
			n.TCP = rn.TCP
		}
	}
	//不一致的话 如果该节点已经与自己相连通，则返回错误
	return n, err
}

// nodeNetGuts is embedded in Node and contains fields.
type nodeNetGuts struct {
	// This is a cached copy of sha3(ID) which is used for node
	// distance calculations. This is part of Node in order to make it
	// possible to write tests that need a node at a certain distance.
	// In those tests, the content of sha will not actually correspond
	// with ID.
	sha common.Hash

	// State machine fields. Access to these fields
	// is restricted to the Network.loop goroutine.
	state      *nodeState
	pingEcho   []byte  // hash of last ping sent by us  ping命令对应的hash值
	pingTopics []Topic // topic set sent by us in last ping

	/* 保存findnodeQuery的请求列表 */
	deferredQueries   []*findnodeQuery // queries that can't be sent yet //延期的消息请求
	pendingNeighbours *findnodeQuery   // current query, waiting for reply
	queryTimeouts     int
}

func (n *nodeNetGuts) deferQuery(q *findnodeQuery) {
	n.deferredQueries = append(n.deferredQueries, q)
}

/* 从缓存中取出下一个请求列表，因为这里是控制并发的所以才有了请求队列 */
/* 这里爆粗了 查找节点的请求 */
func (n *nodeNetGuts) startNextQuery(net *Network) {
	if len(n.deferredQueries) == 0 {
		return
	}
	nextq := n.deferredQueries[0]
	if nextq.start(net) {
		n.deferredQueries = append(n.deferredQueries[:0], n.deferredQueries[1:]...)
	}
}

/* 这里是 findnode方法的逻辑 */
/* 如果从本地查询，则返回本地节点的路由表中n个最近的节点 */
/* 如果从其他节点查询，则返回其他节点上n个 最近的节点 */
func (q *findnodeQuery) start(net *Network) bool {
	// Satisfy queries against the local node directly.
	/* 在当前机器上去查询 */
	if q.remote == net.tab.self {
		closest := net.tab.closest(crypto.Keccak256Hash(q.target[:]), bucketSize)
		q.reply <- closest.entries
		return true
	}
	/* 从远程节点查询 */
	if q.remote.state.canQuery && q.remote.pendingNeighbours == nil {
		net.conn.sendFindnodeHash(q.remote, q.target)
		net.timedEvent(respTimeout, q.remote, neighboursTimeout)
		q.remote.pendingNeighbours = q
		return true
	}
	// If the node is not known yet, it won't accept queries.
	// Initiate the transition to known.
	// The request will be sent later when the node reaches known state.
	if q.remote.state == unknown {
		net.transition(q.remote, verifyinit)
	}
	return false
}

// Node Events (the input to the state machine).

type nodeEvent uint

//go:generate stringer -type=nodeEvent

const (

	// Packet type events.
	// These correspond to packet types in the UDP protocol.
	pingPacket = iota + 1
	pongPacket
	findnodePacket
	neighborsPacket
	findnodeHashPacket
	topicRegisterPacket
	topicQueryPacket
	topicNodesPacket

	// Non-packet events.
	// Event values in this category are allocated outside
	// the packet type range (packet types are encoded as a single byte).
	pongTimeout nodeEvent = iota + 256
	pingTimeout
	neighboursTimeout
)

// Node State Machine.

type nodeState struct {

	/* 当前状态的名称 */
	name string
	/* 当接收到该状态的数据包时，处理数据包 */
	handle func(*Network, *Node, nodeEvent, *ingressPacket) (next *nodeState, err error)
	/* 进入该状态后，首先要执行的操作，可以理解为状态的一种后置拦截器 */
	enter func(*Network, *Node)

	/* 当前状态是否可以发起查询请求 */
	canQuery bool
}

func (s *nodeState) String() string {
	return s.name
}

var (
	unknown          *nodeState // 未知：表示未连接状态
	verifyinit       *nodeState // 发送ping的验证状态信息
	verifywait       *nodeState
	remoteverifywait *nodeState
	known            *nodeState
	contested        *nodeState
	unresponsive     *nodeState
)

func init() {

	/* 节点初始化状态 */
	unknown = &nodeState{
		name: "unknown",

		/* 刚刚进入开状态是的 触发事件 */
		enter: func(net *Network, n *Node) {
			net.tab.delete(n)
			n.pingEcho = nil
			// Abort active .
			for _, q := range n.deferredQueries {
				q.reply <- nil
			}
			n.deferredQueries = nil
			if n.pendingNeighbours != nil {
				n.pendingNeighbours.reply <- nil
				n.pendingNeighbours = nil
			}
			n.queryTimeouts = 0
		},
		/* 当接收到unknown状态的数据包时，处理数据包 */
		handle: func(net *Network, n *Node, ev nodeEvent, pkt *ingressPacket) (*nodeState, error) {
			switch ev {
			case pingPacket:
				net.handlePing(n, pkt)
				net.ping(n, pkt.remoteAddr)
				return verifywait, nil
			default:
				return unknown, errInvalidEvent
			}
		},
	}

	/* 这个状态主要用在 network的刷新方法中，当节点从db中加载进来后，首先讲节点状态设置为 verifyinit(待验证) */
	verifyinit = &nodeState{
		name: "verifyinit",
		/* 流转到该状态时，首先要执行的操作，可以理解为后置拦截器 */
		enter: func(net *Network, n *Node) {
			net.ping(n, n.addr())
		},
		handle: func(net *Network, n *Node, ev nodeEvent, pkt *ingressPacket) (*nodeState, error) {
			switch ev {
			case pingPacket:
				net.handlePing(n, pkt)
				return verifywait, nil
			case pongPacket:
				err := net.handleKnownPong(n, pkt)
				return remoteverifywait, err
			case pongTimeout:
				return unknown, nil
			default:
				return verifyinit, errInvalidEvent
			}
		},
	}

	/* 当节点发送了响应式ping事件(被动ping事件)后，进入该状态 */
	verifywait = &nodeState{
		name: "verifywait",
		handle: func(net *Network, n *Node, ev nodeEvent, pkt *ingressPacket) (*nodeState, error) {
			switch ev {
			case pingPacket:
				net.handlePing(n, pkt)
				return verifywait, nil
			case pongPacket:
				err := net.handleKnownPong(n, pkt)
				return known, err
			case pongTimeout:
				return unknown, nil
			default:
				return verifywait, errInvalidEvent
			}
		},
	}

	remoteverifywait = &nodeState{
		name: "remoteverifywait",
		enter: func(net *Network, n *Node) {
			net.timedEvent(respTimeout, n, pingTimeout)
		},
		handle: func(net *Network, n *Node, ev nodeEvent, pkt *ingressPacket) (*nodeState, error) {
			switch ev {
			case pingPacket:
				net.handlePing(n, pkt)
				return remoteverifywait, nil
			case pingTimeout:
				return known, nil
			default:
				return remoteverifywait, errInvalidEvent
			}
		},
	}

	known = &nodeState{
		name:     "known",
		canQuery: true,

		/* 当与远程节点握手完成后，执行以下处理 */
		enter: func(net *Network, n *Node) {
			n.queryTimeouts = 0
			/* 缓存中保存的 尚未发送的 请求列表 */
			n.startNextQuery(net)

			// Insert into the table and start revalidation of the last node
			// in the bucket if it is full.
			last := net.tab.add(n)
			if last != nil && last.state == known {
				// TODO: do this asynchronously
				net.transition(last, contested)
			}
		},
		handle: func(net *Network, n *Node, ev nodeEvent, pkt *ingressPacket) (*nodeState, error) {
			switch ev {
			case pingPacket:
				net.handlePing(n, pkt)
				return known, nil
			case pongPacket:
				err := net.handleKnownPong(n, pkt)
				return known, err
			default:
				return net.handleQueryEvent(n, ev, pkt)
			}
		},
	}

	//提议
	contested = &nodeState{
		name:     "contested",
		canQuery: true,
		enter: func(net *Network, n *Node) {
			net.ping(n, n.addr())
		},
		handle: func(net *Network, n *Node, ev nodeEvent, pkt *ingressPacket) (*nodeState, error) {
			switch ev {
			case pongPacket:
				// Node is still alive.
				err := net.handleKnownPong(n, pkt)
				return known, err
			case pongTimeout:
				net.tab.deleteReplace(n)
				return unresponsive, nil
			case pingPacket:
				net.handlePing(n, pkt)
				return contested, nil
			default:
				return net.handleQueryEvent(n, ev, pkt)
			}
		},
	}

	unresponsive = &nodeState{
		name:     "unresponsive",
		canQuery: true,
		handle: func(net *Network, n *Node, ev nodeEvent, pkt *ingressPacket) (*nodeState, error) {
			switch ev {
			case pingPacket:
				net.handlePing(n, pkt)
				return known, nil
			case pongPacket:
				err := net.handleKnownPong(n, pkt)
				return known, err
			default:
				return net.handleQueryEvent(n, ev, pkt)
			}
		},
	}
}

// handle processes packets sent by n and events related to n.
func (net *Network) handle(n *Node, ev nodeEvent, pkt *ingressPacket) error {
	//fmt.Println("handle", n.addr().String(), n.state, ev)
	if pkt != nil {
		if err := net.checkPacket(n, ev, pkt); err != nil {
			//fmt.Println("check err:", err)
			return err
		}
		// Start the background expiration goroutine after the first
		// successful communication. Subsequent calls have no effect if it
		// is already running. We do this here instead of somewhere else
		// so that the search for seed nodes also considers older nodes
		// that would otherwise be removed by the expirer.
		if net.db != nil {
			net.db.ensureExpirer()
		}
	}
	if n.state == nil {
		n.state = unknown // 默认远程节点 的状态为  unknown
	}
	/* 处理当前状态的事件，并返回下一个状态 */

	next, err := n.state.handle(net, n, ev, pkt)
	net.transition(n, next)
	//fmt.Println("new state:", n.state)
	return err
}

func (net *Network) checkPacket(n *Node, ev nodeEvent, pkt *ingressPacket) error {
	// Replay prevention checks.
	switch ev {
	case pingPacket, findnodeHashPacket, neighborsPacket:
		// TODO: check date is > last date seen
		// TODO: check ping version
	case pongPacket:
		if !bytes.Equal(pkt.data.(*pong).ReplyTok, n.pingEcho) {
			// fmt.Println("pong reply token mismatch")
			return fmt.Errorf("pong reply token mismatch")
		}
		n.pingEcho = nil
	}
	// Address validation.
	// TODO: Ideally we would do the following:
	//  - reject all packets with wrong address except ping.
	//  - for ping with new address, transition to verifywait but keep the
	//    previous node (with old address) around. if the new one reaches known,
	//    swap it out.
	return nil
}

func (net *Network) transition(n *Node, next *nodeState) {
	/* 如果当前状态与下一个流转的状态不同 */
	if n.state != next {
		n.state = next //切换状态机的状态到下一个状态
		/* 如果进入下一个状态时，拦截器不为空，首先执行拦截器 */
		if next.enter != nil {
			next.enter(net, n)
		}
	}

	// TODO: persist/unpersist node
}

//如果超时，就关闭通道，之前发出的请求回来后 就不用接受其信息
func (net *Network) timedEvent(d time.Duration, n *Node, ev nodeEvent) {
	timeout := timeoutEvent{ev, n}
	net.timeoutTimers[timeout] = time.AfterFunc(d, func() {
		select {
		case net.timeout <- timeout:
		case <-net.closed:
		}
	})
}

func (net *Network) abortTimedEvent(n *Node, ev nodeEvent) {
	timer := net.timeoutTimers[timeoutEvent{ev, n}]
	if timer != nil {
		timer.Stop()
		delete(net.timeoutTimers, timeoutEvent{ev, n})
	}
}

func (net *Network) ping(n *Node, addr *net.UDPAddr) {
	//fmt.Println("ping", n.addr().String(), n.ID.String(), n.sha.Hex())
	/* n.pingEcho 指的是当前ping命令的hash值,如果不为空，代表已经发送过ping请求了 */
	if n.pingEcho != nil || n.ID == net.tab.self.ID {
		//fmt.Println(" not sent")
		return
	}
	log.Trace("Pinging remote node", "node", n.ID)
	/* 发送ping时，首先要获取所有已经注册过的topic主题，why?这是为啥 */
	/* 这里主要是告诉其他节点，我只接受什么类型的请求 */
	n.pingTopics = net.ticketStore.regTopicSet()
	/* 调用udp网络层，将ping命令发送出去 */
	n.pingEcho = net.conn.sendPing(n, addr, n.pingTopics)
	/* 为当前的ping设置超时监听器 */
	net.timedEvent(respTimeout, n, pongTimeout)
}

/**
 * 处理对方发送过来的ping消息
 * @param n 发送方的节点
 * @param pkt  network的接收到的数据包
 * 处理接收到的ping消息
 *
 */
func (net *Network) handlePing(n *Node, pkt *ingressPacket) {
	log.Trace("Handling remote ping", "node", n.ID)

	/* 获取 远程节点的 tcp端口 */
	ping := pkt.data.(*ping)
	n.TCP = ping.From.TCP

	// 从本地获取 远程节点 的topics
	t := net.topictab.getTicket(n, ping.Topics)

	// 封装一个pong数据包
	pong := &pong{
		To: makeEndpoint(n.addr(), n.TCP), // TODO: maybe use known TCP port from DB对方的地址信息
		/* 将远程节点的 数据签名 作为 token，以方便校验是对哪个数据包的相应 */
		ReplyTok: pkt.hash, // 发送方传递过来的摘要信息
		/* 添加 timeout事件， */
		Expiration: uint64(time.Now().Add(expiration).Unix()), // 过期时间20秒
	}

	// 将本地的 已经注册的topic 封装到 pong数据包中
	ticketToPong(t, pong)

	//将数据包pong发送出去
	net.conn.send(n, pongPacket, pong)
}

func (net *Network) handleKnownPong(n *Node, pkt *ingressPacket) error {
	log.Trace("Handling known pong", "node", n.ID)
	net.abortTimedEvent(n, pongTimeout)
	now := mclock.Now()
	ticket, err := pongToTicket(now, n.pingTopics, n, pkt)
	if err == nil {
		// fmt.Printf("(%x) ticket: %+v\n", net.tab.self.ID[:8], pkt.data)
		net.ticketStore.addTicket(now, pkt.data.(*pong).ReplyTok, ticket)
	} else {
		log.Trace("Failed to convert pong to ticket", "err", err)
	}
	n.pingEcho = nil
	n.pingTopics = nil
	return err
}

//根据节点请求的类型来处理
func (net *Network) handleQueryEvent(n *Node, ev nodeEvent, pkt *ingressPacket) (*nodeState, error) {
	switch ev {
	/* 查询目标节点的n个邻居节点 */
	case findnodePacket:
		target := crypto.Keccak256Hash(pkt.data.(*findnode).Target[:])

		//找到离节点target最近的16个节点
		results := net.tab.closest(target, bucketSize).entries
		net.conn.sendNeighbours(n, results)
		return n.state, nil
	case neighborsPacket:
		err := net.handleNeighboursPacket(n, pkt)
		return n.state, err
	case neighboursTimeout:
		if n.pendingNeighbours != nil {
			n.pendingNeighbours.reply <- nil
			n.pendingNeighbours = nil
		}
		n.queryTimeouts++
		if n.queryTimeouts > maxFindnodeFailures && n.state == known {
			return contested, errors.New("too many timeouts")
		}
		return n.state, nil

	// v5
	/* 根据节点的hashid查找其最近的n个节点，这个与findnodePacket原理是一样的，只不过传递过来的参数不同 */
	/* 这里也表示查询数据，查询某资源可能存在的邻居节点 */
	case findnodeHashPacket:
		results := net.tab.closest(pkt.data.(*findnodeHash).Target, bucketSize).entries
		net.conn.sendNeighbours(n, results)
		return n.state, nil
	case topicRegisterPacket:
		//fmt.Println("got topicRegisterPacket")
		regdata := pkt.data.(*topicRegister)
		pong, err := net.checkTopicRegister(regdata)
		if err != nil {
			//fmt.Println(err)
			return n.state, fmt.Errorf("bad waiting ticket: %v", err)
		}
		net.topictab.useTicket(n, pong.TicketSerial, regdata.Topics, int(regdata.Idx), pong.Expiration, pong.WaitPeriods)
		return n.state, nil
	case topicQueryPacket:
		// TODO: handle expiration
		topic := pkt.data.(*topicQuery).Topic
		results := net.topictab.getEntries(topic)
		if _, ok := net.ticketStore.tickets[topic]; ok {
			results = append(results, net.tab.self) // we're not registering in our own table but if we're advertising, return ourselves too
		}
		if len(results) > 10 {
			results = results[:10]
		}
		var hash common.Hash
		copy(hash[:], pkt.hash)
		net.conn.sendTopicNodes(n, hash, results)
		return n.state, nil
	case topicNodesPacket:
		p := pkt.data.(*topicNodes)
		if net.ticketStore.gotTopicNodes(n, p.Echo, p.Nodes) {
			n.queryTimeouts++
			if n.queryTimeouts > maxFindnodeFailures && n.state == known {
				return contested, errors.New("too many timeouts")
			}
		}
		return n.state, nil

	default:
		return n.state, errInvalidEvent
	}
}

//检查注册
func (net *Network) checkTopicRegister(data *topicRegister) (*pong, error) {
	var pongpkt ingressPacket
	if err := decodePacket(data.Pong, &pongpkt); err != nil {
		return nil, err
	}
	if pongpkt.ev != pongPacket {
		return nil, errors.New("is not pong packet")
	}
	if pongpkt.remoteID != net.tab.self.ID {
		return nil, errors.New("not signed by us")
	}
	// check that we previously authorised all topics
	// that the other side is trying to register.
	if rlpHash(data.Topics) != pongpkt.data.(*pong).TopicHash {
		return nil, errors.New("topic hash mismatch")
	}

	//检查是否保存的订阅已经达到最大了
	if data.Idx < 0 || int(data.Idx) >= len(data.Topics) {
		return nil, errors.New("topic index out of range")
	}
	return pongpkt.data.(*pong), nil
}

func rlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewKeccak256()
	//编码，并取回第一个字节
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}

func (net *Network) handleNeighboursPacket(n *Node, pkt *ingressPacket) error {
	if n.pendingNeighbours == nil {
		return errNoQuery
	}

	//停止超时监听
	net.abortTimedEvent(n, neighboursTimeout)

	//找到请求中带过来的节点
	req := pkt.data.(*neighbors)
	nodes := make([]*Node, len(req.Nodes))

	//遍历请求中的节点
	for i, rn := range req.Nodes {
		nn, err := net.internNodeFromNeighbours(pkt.remoteAddr, rn)
		if err != nil {
			log.Debug(fmt.Sprintf("invalid neighbour (%v) from %x@%v: %v", rn.IP, n.ID[:8], pkt.remoteAddr, err))
			continue
		}
		nodes[i] = nn
		// Start validation of query results immediately.
		// This fills the table quickly.
		// TODO: generates way too many packets, maybe do it via queue.
		if nn.state == unknown {
			net.transition(nn, verifyinit)
		}
	}
	// TODO: don't ignore second packet
	n.pendingNeighbours.reply <- nodes
	n.pendingNeighbours = nil
	// Now that this query is done, start the next one.
	n.startNextQuery(net)
	return nil
}
