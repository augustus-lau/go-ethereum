// Copyright 2014 The go-ethereum Authors
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

// Package p2p implements the Ethereum p2p network protocols.
package p2p

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/discv5"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

/**
 *  这从p2p的服务 启动开始研究
 *  1、节点服务启动需要什么配置
 *  2、节点服务启动的同时初始化了什么功能
 *  3、节点服务提供什么服务
 *  4、提供的服务时如何实现的
 */
const (
	defaultDialTimeout = 15 * time.Second //默认通话时间 --连接时间

	// Connectivity defaults.
	maxActiveDialTasks     = 16 //最大的有效的连接任务数量--可以理解为同时多少个任务在请求中，
	defaultMaxPendingPeers = 50 //最大的在等待中的节点

	/* 默认进站与出站的连接数的 比例 */
	defaultDialRatio = 3

	// Maximum time allowed for reading a complete message.
	// This is effectively the amount of time a connection can be idle.
	frameReadTimeout = 30 * time.Second

	// Maximum amount of time allowed for writing a complete message.
	frameWriteTimeout = 20 * time.Second
)

var errServerStopped = errors.New("server stopped")

// Config holds Server options.
type Config struct {
	// This field must be set to a valid secp256k1 private key.
	PrivateKey *ecdsa.PrivateKey `toml:"-"`

	// MaxPeers is the maximum number of peers that can be
	// connected. It must be greater than zero.
	MaxPeers int

	// MaxPendingPeers is the maximum number of peers that can be pending in the
	// handshake phase, counted separately for inbound and outbound connections.
	// Zero defaults to preset values.
	MaxPendingPeers int `toml:",omitempty"`

	// DialRatio controls the ratio of inbound to dialed connections.
	// Example: a DialRatio of 2 allows 1/2 of connections to be dialed.
	// Setting DialRatio to zero defaults it to 3.
	DialRatio int `toml:",omitempty"`

	//是否开始节点的发现机制
	// NoDiscovery can be used to disable the peer discovery mechanism.
	// Disabling is useful for protocol debugging (manual topology).
	NoDiscovery bool

	//是否采用v5版本的 发现机制
	// DiscoveryV5 specifies whether the the new topic-discovery based V5 discovery
	// protocol should be started or not.
	DiscoveryV5 bool `toml:",omitempty"`

	// Name sets the node name of this server.
	// Use common.MakeName to create a name that follows existing conventions.
	Name string `toml:"-"`

	// 守护节点,用于与其他节点建立连接
	// BootstrapNodes are used to establish connectivity
	// with the rest of the network.
	BootstrapNodes []*discover.Node

	// v5版本的守护节点
	// BootstrapNodesV5 are used to establish connectivity
	// with the rest of the network using the V5 discovery
	// protocol.
	BootstrapNodesV5 []*discv5.Node `toml:",omitempty"`

	// 断连后必须重连的节点
	// Static nodes are used as pre-configured connections which are always
	// maintained and re-connected on disconnects.
	StaticNodes []*discover.Node

	//信任节点，即使连接数超过了 最大连接数，这些节点也允许去联通
	// Trusted nodes are used as pre-configured connections which are always
	// allowed to connect, even above the peer limit.
	TrustedNodes []*discover.Node

	// 黑名单
	// Connectivity can be restricted to certain IP networks.
	// If this option is set to a non-nil value, only hosts which match one of the
	// IP networks contained in the list are considered.
	NetRestrict *netutil.Netlist `toml:",omitempty"`

	//保存之前网络中存活的连接地址
	// NodeDatabase is the path to the database containing the previously seen
	// live nodes in the network.
	NodeDatabase string `toml:",omitempty"`

	//这里包含了该节点支持的协议--这个协议指tcp,http等
	// Protocols should contain the protocols supported
	// by the server. Matching protocols are launched for
	// each peer.
	Protocols []Protocol `toml:"-"`

	//监听的地址，ip:port
	// If ListenAddr is set to a non-nil address, the server
	// will listen for incoming connections.
	//
	// If the port is zero, the operating system will pick a port. The
	// ListenAddr field will be updated with the actual address when
	// the server is started.
	ListenAddr string

	//解决内网到外网的转换问题
	// If set to a non-nil value, the given NAT port mapper
	// is used to make the listening port available to the
	// Internet.
	NAT nat.Interface `toml:",omitempty"`

	// TCP端口服务 -- 如果该节点的tcp端口为空，则该节点只负责在集群内部udp链接通信
	// If Dialer is set to a non-nil value, the given Dialer
	// is used to dial outbound peer connections.
	Dialer NodeDialer `toml:"-"`

	// 如果设置为true, 当前节点不会去主动连接其他任何节点
	// If NoDial is true, the server will not dial any peers.
	NoDial bool `toml:",omitempty"`

	//如果设置了EnabrMsgEvsServer，那么每当向对等方发送或接收消息时，服务器将发出PEER事件。
	// If EnableMsgEvents is set then the server will emit PeerEvents
	// whenever a message is sent to or received from a peer
	EnableMsgEvents bool

	// Logger is a custom logger to use with the p2p.Server.
	Logger log.Logger `toml:",omitempty"`
}

// 管理所有对等节点的连接
// Server manages all peer connections.
type Server struct {
	// Config fields may not be modified while the server is running.
	Config

	//这两个是 回调方法
	// Hooks for testing. These are useful because we can inhibit
	// the whole protocol stack.

	//根据 conn，构建逻辑传输层对象
	newTransport func(net.Conn) transport //可以理解为一个保存 其他节点连接对象的通道

	//用于测试 -- 判断peer的id是否合法
	newPeerHook func(*Peer)

	// 全局的锁
	lock sync.Mutex // protects running

	//服务是否已经开启
	running bool

	//路由表  -- 抽象接口
	ntab discoverTable

	// 网络监听器
	listener net.Listener

	//向外发送消息时的协议，这里存储了 与本节点相连的其他节点支持的所有协议
	ourHandshake *protoHandshake

	//最新一次的查询时间
	lastLookup time.Time

	// p2p发现机制第5版本中的 网络对象
	DiscV5 *discv5.Network

	// These are for Peers, PeerCount (and nothing else).
	// peer连接通后发送到该通道
	peerOp chan peerOpFunc

	// peer连接成功后的对象
	peerOpDone chan struct{}

	//其他处理事件的通道
	quit          chan struct{}       //退出
	addstatic     chan *discover.Node //增加静态节点
	removestatic  chan *discover.Node //删除静态节点
	posthandshake chan *conn          //发送握手信息
	addpeer       chan *conn          //增加同伴节点
	delpeer       chan peerDrop       //删除同伴节点
	loopWG        sync.WaitGroup      //锁 --解决协程交互问题
	peerFeed      event.Feed          //订阅消息填充
	log           log.Logger          //日志
}

type peerOpFunc func(map[discover.NodeID]*Peer)

type peerDrop struct {
	*Peer
	err       error
	requested bool // true if signaled by the peer
}

type connFlag int

const (
	dynDialedConn connFlag = 1 << iota
	staticDialedConn
	inboundConn
	trustedConn
)

// conn wraps a network connection with information gathered
// during the two handshakes.
type conn struct {
	fd        net.Conn        //客户端的socket，或者叫句柄
	transport                 //传输协议，tcp采用的是rlp传输协议
	flags     connFlag        //参数
	cont      chan error      // The run loop uses cont to signal errors to SetupConn.  //如果连接有任何错误，都发送到该通道中
	id        discover.NodeID // valid after the encryption handshake  //客户端的id
	caps      []Cap           // valid after the protocol handshake   //客户端支持的协议
	name      string          // valid after the protocol handshake   //客户端的名字
}

/**
 *  逻辑传输层
 *  这里讲两个节点之间的通道抽象为一个逻辑传输通道
 *  conn：可以理解为一个通道，只要连接上就可以发送数据
 *  transport：这是逻辑上的通道，当conn连接上后，这里还要确认连接是否有效，比如加了逻辑验证。如果验证通过，才代表传输层连接通了
 *             如果验证未通过，则应该关闭conn。
 */
type transport interface {
	// The two handshakes.
	//通过这个方法来完成交换密钥，创建加密信道的流程。如果失败，那么链接关闭。
	doEncHandshake(prv *ecdsa.PrivateKey, dialDest *discover.Node) (discover.NodeID, error)

	//这个方法来进行协议特性之间的协商，比如双方的协议版本，是否支持Snappy加密方式等操作
	doProtoHandshake(our *protoHandshake) (*protoHandshake, error)
	// The MsgReadWriter can only be used after the encryption
	// handshake has completed. The code uses conn.id to track this
	// by setting it to a non-nil value after the encryption handshake.

	//如果以上两个方法都通过，就说明连接已经建立

	// 传输层的流
	MsgReadWriter
	// transports must provide Close because we use MsgPipe in some of
	// the tests. Closing the actual network connection doesn't do
	// anything in those tests because NsgPipe doesn't use it.
	//关闭传输层
	close(err error)
}

func (c *conn) String() string {
	s := c.flags.String()
	if (c.id != discover.NodeID{}) {
		s += " " + c.id.String()
	}
	s += " " + c.fd.RemoteAddr().String()
	return s
}

func (f connFlag) String() string {
	s := ""
	if f&trustedConn != 0 {
		s += "-trusted"
	}
	if f&dynDialedConn != 0 {
		s += "-dyndial"
	}
	if f&staticDialedConn != 0 {
		s += "-staticdial"
	}
	if f&inboundConn != 0 {
		s += "-inbound"
	}
	if s != "" {
		s = s[1:]
	}
	return s
}

func (c *conn) is(f connFlag) bool {
	return c.flags&f != 0
}

// 返回已经连接的所有节点 -- 采用了通道的方式来统计的？为什么？
// 当前对peer的所有操作都采用通道方式处理，主要是为了解决多线程问题
// Peers returns all connected peers.
func (srv *Server) Peers() []*Peer {
	var ps []*Peer
	select {
	// Note: We'd love to put this function into a variable but
	// that seems to cause a weird compiler error in some
	// environments.
	case srv.peerOp <- func(peers map[discover.NodeID]*Peer) {
		for _, p := range peers {
			ps = append(ps, p)
		}
	}:
		// 将该peer的对象从done中删除掉 -- 这里不明白
		<-srv.peerOpDone
	case <-srv.quit: //如果该通道不为空
	}
	return ps
}

// 统计当前服务连接了多少节点 也要用通道么
// 当前对peer的所有操作都采用通道方式处理，主要是为了解决多线程问题
// PeerCount returns the number of connected peers.
func (srv *Server) PeerCount() int {
	var count int
	select {
	case srv.peerOp <- func(ps map[discover.NodeID]*Peer) { count = len(ps) }:
		// 将该peer的对象从done中删除掉
		<-srv.peerOpDone
	case <-srv.quit:
	}
	return count
}

// 添加一个节点，并连接
// AddPeer connects to the given node and maintains the connection until the
// server is shut down. If the connection fails for any reason, the server will
// attempt to reconnect the peer.
func (srv *Server) AddPeer(node *discover.Node) {
	select {
	case srv.addstatic <- node:
	case <-srv.quit:
	}
}

// 删除已经连接的对象
// RemovePeer disconnects from the given node
func (srv *Server) RemovePeer(node *discover.Node) {
	select {
	case srv.removestatic <- node:
	case <-srv.quit:
	}
}

// 用于广播
// 添加订阅的事件 -- 当对方的peer有相应的事件传递过来后，会放入对应的通道中
// SubscribePeers subscribes the given channel to peer events
func (srv *Server) SubscribeEvents(ch chan *PeerEvent) event.Subscription {
	return srv.peerFeed.Subscribe(ch)
}

// 返回当前服务器的信息 --
// Self returns the local node's endpoint information.
func (srv *Server) Self() *discover.Node {
	srv.lock.Lock()
	defer srv.lock.Unlock()

	if !srv.running {
		return &discover.Node{IP: net.ParseIP("0.0.0.0")}
	}
	return srv.makeSelf(srv.listener, srv.ntab)
}

func (srv *Server) makeSelf(listener net.Listener, ntab discoverTable) *discover.Node {
	// If the server's not running, return an empty node.
	// If the node is running but discovery is off, manually assemble the node infos.
	if ntab == nil {
		// Inbound connections disabled, use zero address.
		if listener == nil {
			return &discover.Node{IP: net.ParseIP("0.0.0.0"), ID: discover.PubkeyID(&srv.PrivateKey.PublicKey)}
		}
		// Otherwise inject the listener address too
		addr := listener.Addr().(*net.TCPAddr)
		return &discover.Node{
			ID:  discover.PubkeyID(&srv.PrivateKey.PublicKey),
			IP:  addr.IP,
			TCP: uint16(addr.Port),
		}
	}
	// Otherwise return the discovery node.
	return ntab.Self()
}

// Stop terminates the server and all active peer connections.
// It blocks until all active connections have been closed.
func (srv *Server) Stop() {
	srv.lock.Lock()
	defer srv.lock.Unlock()
	if !srv.running {
		return
	}
	srv.running = false
	if srv.listener != nil {
		// this unblocks listener Accept
		srv.listener.Close()
	}
	close(srv.quit)
	srv.loopWG.Wait()
}

// 对于不做任何处理的 信息，我们统一放到一个channel中， 这样是为了提高效率，因为这部分消息只读，不需要回复。
// 我们把这个channel叫做共享无需回复通道 --- 只针对UDP端口
// sharedUDPConn implements a shared connection. Write sends messages to the underlying connection while read returns
// messages that were found unprocessable and sent to the unhandled channel by the primary listener.
type sharedUDPConn struct {
	*net.UDPConn
	unhandled chan discover.ReadPacket
}

// 从 sharedUDPConn 读取 接收到的数据
// ReadFromUDP implements discv5.conn
/**
 * @return n    表示接收到的数据大小
 * @return addr 表示数据的来源
 *
 */
func (s *sharedUDPConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {

	//从共享无需回复通道中获取一条数据
	packet, ok := <-s.unhandled
	if !ok {
		return 0, nil, fmt.Errorf("Connection was closed")
	}
	l := len(packet.Data)
	if l > len(b) {
		l = len(b)
	}
	copy(b[:l], packet.Data[:l])
	return l, packet.Addr, nil
}

// Close implements discv5.conn
func (s *sharedUDPConn) Close() error {
	return nil
}

// 启动该节点
// Start starts running the server.
// Servers can not be re-used after stopping.
func (srv *Server) Start() (err error) {
	srv.lock.Lock()
	defer srv.lock.Unlock()
	if srv.running {
		return errors.New("server already running")
	}
	srv.running = true
	srv.log = srv.Config.Logger
	if srv.log == nil {
		srv.log = log.New()
	}
	srv.log.Info("Starting P2P networking")

	// static fields
	if srv.PrivateKey == nil {
		return fmt.Errorf("Server.PrivateKey must be set to a non-nil key")
	}

	//默认初始化 传输通道 为 rlpx -- 用于udp，tcp(不是http)传输
	if srv.newTransport == nil {
		srv.newTransport = newRLPX
	}

	//go中创建一个tcp连接的 方式 --- 这里并没有开启tcp，只是封装了下
	if srv.Dialer == nil {
		srv.Dialer = TCPDialer{&net.Dialer{Timeout: defaultDialTimeout}}
	}

	// 初始化 channel
	srv.quit = make(chan struct{})
	srv.addpeer = make(chan *conn)
	srv.delpeer = make(chan peerDrop)
	srv.posthandshake = make(chan *conn)
	srv.addstatic = make(chan *discover.Node)
	srv.removestatic = make(chan *discover.Node)
	srv.peerOp = make(chan peerOpFunc)   //操作peer的通道，只要是对peer的修改操作都放到该通道中
	srv.peerOpDone = make(chan struct{}) //操作peer完毕的通知通道。当操作peer完毕后，在这里放一个信号，以方便通知其他线程操作

	var (
		conn      *net.UDPConn
		sconn     *sharedUDPConn
		realaddr  *net.UDPAddr
		unhandled chan discover.ReadPacket
	)

	//////////////////////////////////初始化 Discover ////////////////Start//////////////////////////////////////////////////
	/**
	 * !srv.NoDiscovery || srv.DiscoveryV5
	 * 这个是判断是否需要开始自动发现机制
	 */
	// 判断是否开始发现机制，如果开启则初始化UDP(发现机制主要采用udp来创建)
	if !srv.NoDiscovery || srv.DiscoveryV5 {

		// 解析udp的端口地址
		addr, err := net.ResolveUDPAddr("udp", srv.ListenAddr)
		if err != nil {
			return err
		}
		//开启一个udp的端口---这个udp 只用于discover，所以要把它传递给discover对象
		conn, err = net.ListenUDP("udp", addr)
		if err != nil {
			return err
		}
		realaddr = conn.LocalAddr().(*net.UDPAddr)

		// 如果是在nat环境下 --- 这需要了解nat环境
		if srv.NAT != nil {
			if !realaddr.IP.IsLoopback() {
				go nat.Map(srv.NAT, srv.quit, "udp", realaddr.Port, realaddr.Port, "ethereum discovery")
			}
			//获取本机的外网地址
			// TODO: react to external IP changes over time.
			if ext, err := srv.NAT.ExternalIP(); err == nil {
				realaddr = &net.UDPAddr{IP: ext, Port: realaddr.Port}
			}
		}
	}

	//如果开了发现机制 -- 在udp端口 开一个100大小的channel， 用于接受不做任何处理的信息
	if !srv.NoDiscovery && srv.DiscoveryV5 {
		unhandled = make(chan discover.ReadPacket, 100)
		sconn = &sharedUDPConn{conn, unhandled}
	}

	// srv.NoDiscovery = false, 不启用  自动发现机制时 ---- 非加密方式启动
	// 那么这时候 主要是从db里获取种子节点来维护路由表信息
	if !srv.NoDiscovery {

		//节点发现机制的配置
		cfg := discover.Config{
			PrivateKey:   srv.PrivateKey,     //私钥
			AnnounceAddr: realaddr,           //真实地址
			NodeDBPath:   srv.NodeDatabase,   //本节点的数据库地址
			NetRestrict:  srv.NetRestrict,    //本节点的黑名单
			Bootnodes:    srv.BootstrapNodes, //本节点的守护节点地址
			Unhandled:    unhandled,          //无用信息的处理通道
		}

		// 根据以上配置 初始化udp对象---- 这里采用不加密的方式进行udp数据传输
		// 主要是讲udp的连接进一步封装，然后启动配置中的db, 初始化本地路由表等---返回本节点的路由表
		// 单独启动一个线程来监听
		ntab, err := discover.ListenUDP(conn, cfg) //这是旧版本的 udp处理方式
		if err != nil {
			return err
		}
		srv.ntab = ntab
	}

	////// 到这里为止，udp已经启动，而且可以接受请求。table的loop循环也已经开始工作///////////////////////

	//上面是 不启用自动发现机制时  discover的创建，这里是启用 自动发现机制时，discover的创建
	// 上方的并未加密， ------加密方式启动
	if srv.DiscoveryV5 {
		var (
			ntab *discv5.Network
			err  error
		)

		//新版本的udp处理方式
		//如果sconn 不为空，存在 不响应数据通道时，该共享udp连接也要加密
		if sconn != nil {
			ntab, err = discv5.ListenUDP(srv.PrivateKey, sconn, realaddr, "", srv.NetRestrict) //srv.NodeDatabase)
		} else {
			ntab, err = discv5.ListenUDP(srv.PrivateKey, conn, realaddr, "", srv.NetRestrict) //srv.NodeDatabase)
		}
		if err != nil {
			return err
		}

		/* 当真正添加完守护节点后，路由表的刷新就正式开始。否则有可能路由表的种子节点为空 */
		if err := ntab.SetFallbackNodes(srv.BootstrapNodesV5); err != nil {
			return err
		}
		srv.DiscV5 = ntab
	}

	//////////////////////////////////初始化 Discover ////////////////End//////////////////////////////////////////////////

	//////////////////////////////////初始化  TCP服务 ////////////////Start//////////////////////////////////////////////////

	/* dail tcp的连接数 */
	dynPeers := srv.maxDialedConns()

	/* 生成拨号对象(主动去连接其他节点的对象) */
	dialer := newDialState(srv.StaticNodes, srv.BootstrapNodes, srv.ntab, dynPeers, srv.NetRestrict)

	// handshake  -- tcp端口 连接 需要采用的协议
	srv.ourHandshake = &protoHandshake{Version: baseProtocolVersion, Name: srv.Name, ID: discover.PubkeyID(&srv.PrivateKey.PublicKey)}

	//添加上本节点支持的 所有协议
	for _, p := range srv.Protocols {
		srv.ourHandshake.Caps = append(srv.ourHandshake.Caps, p.cap())
	}

	// 启动本节点的rpc服务
	if srv.ListenAddr != "" {
		if err := srv.startListening(); err != nil {
			return err
		}
	}
	if srv.NoDial && srv.ListenAddr == "" {
		srv.log.Warn("P2P server will be useless, neither dialing nor listening")
	}

	//启动一个线程来接受tcp的请求
	srv.loopWG.Add(1)

	/* 启动拨号器的调度 */
	go srv.run(dialer)
	srv.running = true

	//////////////////////////////////初始化  TCP服务 ////////////////End//////////////////////////////////////////////////

	return nil
}

// 启动tcp的监听器， 也就是启动tcp服务
func (srv *Server) startListening() error {
	// Launch the TCP listener.
	listener, err := net.Listen("tcp", srv.ListenAddr)
	if err != nil {
		return err
	}
	laddr := listener.Addr().(*net.TCPAddr)
	srv.ListenAddr = laddr.String()
	srv.listener = listener

	//解决go协程 同步的问题
	srv.loopWG.Add(1)

	//协程 loop监听
	go srv.listenLoop()
	// Map the TCP listening port if NAT is configured.
	if !laddr.IP.IsLoopback() && srv.NAT != nil {
		srv.loopWG.Add(1)
		go func() {
			nat.Map(srv.NAT, srv.quit, "tcp", laddr.Port, laddr.Port, "ethereum p2p")
			srv.loopWG.Done()
		}()
	}
	return nil
}

type dialer interface {
	newTasks(running int, peers map[discover.NodeID]*Peer, now time.Time) []task
	taskDone(task, time.Time)
	addStatic(*discover.Node)
	removeStatic(*discover.Node)
}

func (srv *Server) run(dialstate dialer) {
	defer srv.loopWG.Done()
	var (
		peers        = make(map[discover.NodeID]*Peer)
		inboundCount = 0
		trusted      = make(map[discover.NodeID]bool, len(srv.TrustedNodes))
		taskdone     = make(chan task, maxActiveDialTasks)
		runningTasks []task
		queuedTasks  []task // tasks that can't run yet
	)
	// Put trusted nodes into a map to speed up checks.
	// Trusted peers are loaded on startup and cannot be
	// modified while the server is running.
	for _, n := range srv.TrustedNodes {
		trusted[n.ID] = true
	}

	// removes t from runningTasks
	delTask := func(t task) {
		for i := range runningTasks {
			if runningTasks[i] == t {
				runningTasks = append(runningTasks[:i], runningTasks[i+1:]...)
				break
			}
		}
	}
	// starts until max number of active tasks is satisfied
	startTasks := func(ts []task) (rest []task) {
		i := 0
		for ; len(runningTasks) < maxActiveDialTasks && i < len(ts); i++ {
			t := ts[i]
			srv.log.Trace("New dial task", "task", t)
			go func() { t.Do(srv); taskdone <- t }()
			runningTasks = append(runningTasks, t)
		}
		return ts[i:]
	}
	scheduleTasks := func() {
		// Start from queue first.
		queuedTasks = append(queuedTasks[:0], startTasks(queuedTasks)...)
		// Query dialer for new tasks and start as many as possible now.
		if len(runningTasks) < maxActiveDialTasks {
			nt := dialstate.newTasks(len(runningTasks)+len(queuedTasks), peers, time.Now())
			queuedTasks = append(queuedTasks, startTasks(nt)...)
		}
	}

running:
	for {
		scheduleTasks()

		select {
		case <-srv.quit:
			// The server was stopped. Run the cleanup logic.
			break running
		case n := <-srv.addstatic:
			// This channel is used by AddPeer to add to the
			// ephemeral static peer list. Add it to the dialer,
			// it will keep the node connected.
			srv.log.Debug("Adding static node", "node", n)
			dialstate.addStatic(n)
		case n := <-srv.removestatic:
			// This channel is used by RemovePeer to send a
			// disconnect request to a peer and begin the
			// stop keeping the node connected
			srv.log.Debug("Removing static node", "node", n)
			dialstate.removeStatic(n)
			if p, ok := peers[n.ID]; ok {
				p.Disconnect(DiscRequested)
			}
		case op := <-srv.peerOp:
			// This channel is used by Peers and PeerCount.
			op(peers)
			srv.peerOpDone <- struct{}{}
		case t := <-taskdone:
			// A task got done. Tell dialstate about it so it
			// can update its state and remove it from the active
			// tasks list.
			srv.log.Trace("Dial task done", "task", t)
			dialstate.taskDone(t, time.Now())
			delTask(t)
		case c := <-srv.posthandshake:
			// A connection has passed the encryption handshake so
			// the remote identity is known (but hasn't been verified yet).
			if trusted[c.id] {
				// Ensure that the trusted flag is set before checking against MaxPeers.
				c.flags |= trustedConn
			}
			// TODO: track in-progress inbound node IDs (pre-Peer) to avoid dialing them.
			select {
			case c.cont <- srv.encHandshakeChecks(peers, inboundCount, c):
			case <-srv.quit:
				break running
			}
		case c := <-srv.addpeer:
			// At this point the connection is past the protocol handshake.
			// Its capabilities are known and the remote identity is verified.
			err := srv.protoHandshakeChecks(peers, inboundCount, c)
			if err == nil {
				// The handshakes are done and it passed all checks.
				p := newPeer(c, srv.Protocols)
				// If message events are enabled, pass the peerFeed
				// to the peer
				if srv.EnableMsgEvents {
					p.events = &srv.peerFeed
				}
				name := truncateName(c.name)
				srv.log.Debug("Adding p2p peer", "name", name, "addr", c.fd.RemoteAddr(), "peers", len(peers)+1)
				go srv.runPeer(p)
				peers[c.id] = p
				if p.Inbound() {
					inboundCount++
				}
			}
			// The dialer logic relies on the assumption that
			// dial tasks complete after the peer has been added or
			// discarded. Unblock the task last.
			select {
			case c.cont <- err:
			case <-srv.quit:
				break running
			}
		case pd := <-srv.delpeer:
			// A peer disconnected.
			d := common.PrettyDuration(mclock.Now() - pd.created)
			pd.log.Debug("Removing p2p peer", "duration", d, "peers", len(peers)-1, "req", pd.requested, "err", pd.err)
			delete(peers, pd.ID())
			if pd.Inbound() {
				inboundCount--
			}
		}
	}

	srv.log.Trace("P2P networking is spinning down")

	// Terminate discovery. If there is a running lookup it will terminate soon.
	if srv.ntab != nil {
		srv.ntab.Close()
	}
	if srv.DiscV5 != nil {
		srv.DiscV5.Close()
	}
	// Disconnect all peers.
	for _, p := range peers {
		p.Disconnect(DiscQuitting)
	}
	// Wait for peers to shut down. Pending connections and tasks are
	// not handled here and will terminate soon-ish because srv.quit
	// is closed.
	for len(peers) > 0 {
		p := <-srv.delpeer
		p.log.Trace("<-delpeer (spindown)", "remainingTasks", len(runningTasks))
		delete(peers, p.ID())
	}
}

func (srv *Server) protoHandshakeChecks(peers map[discover.NodeID]*Peer, inboundCount int, c *conn) error {
	// Drop connections with no matching protocols.
	if len(srv.Protocols) > 0 && countMatchingProtocols(srv.Protocols, c.caps) == 0 {
		return DiscUselessPeer
	}
	// Repeat the encryption handshake checks because the
	// peer set might have changed between the handshakes.
	return srv.encHandshakeChecks(peers, inboundCount, c)
}

func (srv *Server) encHandshakeChecks(peers map[discover.NodeID]*Peer, inboundCount int, c *conn) error {
	switch {
	case !c.is(trustedConn|staticDialedConn) && len(peers) >= srv.MaxPeers:
		return DiscTooManyPeers
	case !c.is(trustedConn) && c.is(inboundConn) && inboundCount >= srv.maxInboundConns():
		return DiscTooManyPeers
	case peers[c.id] != nil:
		return DiscAlreadyConnected
	case c.id == srv.Self().ID:
		return DiscSelf
	default:
		return nil
	}
}

func (srv *Server) maxInboundConns() int {
	return srv.MaxPeers - srv.maxDialedConns()
}

func (srv *Server) maxDialedConns() int {
	/* 如果不启动发现机制 */
	if srv.NoDiscovery || srv.NoDial {
		return 0
	}
	r := srv.DialRatio
	if r == 0 {
		r = defaultDialRatio
	}
	return srv.MaxPeers / r
}

type tempError interface {
	Temporary() bool
}

/* tcp端口的监听器 */
// listenLoop runs in its own goroutine and accepts
// inbound connections.
func (srv *Server) listenLoop() {
	defer srv.loopWG.Done()
	srv.log.Info("RLPx listener up", "self", srv.makeSelf(srv.listener, srv.ntab))

	/* 设置最大的等待中的连接 */
	tokens := defaultMaxPendingPeers

	// 配置文件中最大的等待连接 设置
	if srv.MaxPendingPeers > 0 {
		tokens = srv.MaxPendingPeers
	}

	// 创建一个 tokens大小的缓冲区，保存正在等待的连接请求
	slots := make(chan struct{}, tokens)

	/* 先将缓冲区放满空数据，当每次循环开始时，就取出一个空对象，这样缓冲区中就只剩一个空缺位置，来保证每次只能进连接一个请求。这样是为了控制并发 */
	/* 我叫它 卡槽设置，是一种无锁的并发控制 */
	for i := 0; i < tokens; i++ {
		slots <- struct{}{}
	}

	//无线循环
	for {
		// Wait for a handshake slot before accepting.
		<-slots

		var (
			fd  net.Conn
			err error
		)

		// 接收到连接后-- 首先判断连接是否有中断等错误
		for {
			fd, err = srv.listener.Accept()
			if tempErr, ok := err.(tempError); ok && tempErr.Temporary() {
				srv.log.Debug("Temporary read error", "err", err)
				continue
			} else if err != nil {
				srv.log.Debug("Read error", "err", err)
				return
			}
			break
		}

		// 如果有网络限制，即黑名单
		// Reject connections that do not match NetRestrict.
		if srv.NetRestrict != nil {
			if tcp, ok := fd.RemoteAddr().(*net.TCPAddr); ok && !srv.NetRestrict.Contains(tcp.IP) {
				srv.log.Debug("Rejected conn (not whitelisted in NetRestrict)", "addr", fd.RemoteAddr())
				fd.Close()

				/* 将卡槽填满，控制并发 */
				slots <- struct{}{}
				continue
			}
		}

		/* 封装一下tcp的连接 */
		fd = newMeteredConn(fd, true)
		srv.log.Trace("Accepted connection", "addr", fd.RemoteAddr())

		/* 协程处理请求，nio模式 */
		go func() {

			/* 以进站方式 连接 */
			srv.SetupConn(fd, inboundConn, nil)
			/* 处理完成后，填充满卡槽 */
			slots <- struct{}{}
		}()
	}
}

// SetupConn runs the handshakes and attempts to add the connection
// as a peer. It returns when the connection has been added as a peer
// or the handshakes have failed.
func (srv *Server) SetupConn(fd net.Conn, flags connFlag, dialDest *discover.Node) error {
	self := srv.Self()
	if self == nil {
		return errors.New("shutdown")
	}

	// 创建一个自身封装的连接
	c := &conn{fd: fd, transport: srv.newTransport(fd), flags: flags, cont: make(chan error)}

	// 这一步就是 将客户段socket封装成peer对象，并保存到本地的缓存中
	err := srv.setupConn(c, flags, dialDest)
	if err != nil {
		c.close(err)
		srv.log.Trace("Setting up connection failed", "id", c.id, "err", err)
	}
	return err
}

// 建立连接-- ，就是将客户端过来的socket封装，并保存到本地
func (srv *Server) setupConn(c *conn, flags connFlag, dialDest *discover.Node) error {
	// Prevent leftover pending conns from entering the handshake.
	srv.lock.Lock()
	running := srv.running
	srv.lock.Unlock()
	if !running {
		return errServerStopped
	}

	// 创建加密的的握手的步骤如下：
	// Run the encryption handshake.
	var err error

	// 第一步：发送本地私钥到对方节点-- 并且让对方发送对方的id
	if c.id, err = c.doEncHandshake(srv.PrivateKey, dialDest); err != nil {
		srv.log.Trace("Failed RLPx handshake", "addr", c.fd.RemoteAddr(), "conn", c.flags, "err", err)
		return err
	}

	clog := srv.log.New("id", c.id, "addr", c.fd.RemoteAddr(), "conn", c.flags)

	// 第二步：检查返回的id ，与 socket中读取的id是否相同
	// For dialed connections, check that the remote public key matches.
	if dialDest != nil && c.id != dialDest.ID {
		clog.Trace("Dialed identity mismatch", "want", c, dialDest.ID)
		return DiscUnexpectedIdentity
	}
	// 第三步：没看懂  检查posthandshake 协议
	err = srv.checkpoint(c, srv.posthandshake)
	if err != nil {
		clog.Trace("Rejected peer before protocol handshake", "err", err)
		return err
	}

	// 第四步 ： 检查ourHandshake协议 -- 让对方返回其支持的所有协议
	// Run the protocol handshake
	phs, err := c.doProtoHandshake(srv.ourHandshake)
	if err != nil {
		clog.Trace("Failed proto handshake", "err", err)
		return err
	}
	if phs.ID != c.id {
		clog.Trace("Wrong devp2p handshake identity", "err", phs.ID)
		return DiscUnexpectedIdentity
	}

	// 保存对方节点支持的协议名称，及协议的版本号
	c.caps, c.name = phs.Caps, phs.Name

	// 第五步：连接已经建立，保存到本地的peer缓存中
	err = srv.checkpoint(c, srv.addpeer)
	if err != nil {
		clog.Trace("Rejected peer", "err", err)
		return err
	}
	// If the checks completed successfully, runPeer has now been
	// launched by run.
	clog.Trace("connection set up", "inbound", dialDest == nil)
	return nil
}

func truncateName(s string) string {
	if len(s) > 20 {
		return s[:20] + "..."
	}
	return s
}

//主要是检查通到中是否有错误
// checkpoint sends the conn to run, which performs the
// post-handshake checks for the stage (posthandshake, addpeer).
func (srv *Server) checkpoint(c *conn, stage chan<- *conn) error {
	select {
	case stage <- c:
	case <-srv.quit:
		return errServerStopped
	}
	select {
	case err := <-c.cont:
		return err
	case <-srv.quit:
		return errServerStopped
	}
}

// 用本地服务 启动peer服务
// runPeer runs in its own goroutine for each peer.
// it waits until the Peer logic returns and removes
// the peer.
func (srv *Server) runPeer(p *Peer) {
	if srv.newPeerHook != nil {
		srv.newPeerHook(p)
	}

	//广播，如果本地服务添加了一个peer，那么就全网广播，让其他节点也添加该peer
	//当广播出去后，其他节点就会根据kad算法来决定是否添加
	// broadcast peer add
	srv.peerFeed.Send(&PeerEvent{
		Type: PeerEventTypeAdd,
		Peer: p.ID(),
	})

	// 启动peer节点----------- 这里没理解为什么会有个启动对方的节点
	// run the protocol
	// --一直阻塞，知道有错误产生
	remoteRequested, err := p.run()

	// 如果上面产生错误-- 则广播该节点有问题，并说明该节点的错误类型
	// broadcast peer drop
	srv.peerFeed.Send(&PeerEvent{
		Type:  PeerEventTypeDrop,
		Peer:  p.ID(),
		Error: err.Error(),
	})

	// Note: run waits for existing peers to be sent on srv.delpeer
	// before returning, so this send should not select on srv.quit.
	srv.delpeer <- peerDrop{p, err, remoteRequested}
}

// 从请求信息里得出的 peer节点信息
// NodeInfo represents a short summary of the information known about the host.
type NodeInfo struct {
	ID    string `json:"id"`    // Unique node identifier (also the encryption key)
	Name  string `json:"name"`  // Name of the node, including client type, version, OS, custom data
	Enode string `json:"enode"` // Enode URL for adding this peer from remote peers
	IP    string `json:"ip"`    // IP address of the node
	Ports struct {
		Discovery int `json:"discovery"` // UDP listening port for discovery protocol
		Listener  int `json:"listener"`  // TCP listening port for RLPx
	} `json:"ports"`
	ListenAddr string                 `json:"listenAddr"`
	Protocols  map[string]interface{} `json:"protocols"` //这是保存 协议名 --> 改协议的对应的处理handler
}

// 返回该节点的基本信息
// NodeInfo gathers and returns a collection of metadata known about the host.
func (srv *Server) NodeInfo() *NodeInfo {
	node := srv.Self()

	// Gather and assemble the generic node infos
	info := &NodeInfo{
		Name:       srv.Name,
		Enode:      node.String(),
		ID:         node.ID.String(),
		IP:         node.IP.String(),
		ListenAddr: srv.ListenAddr,
		Protocols:  make(map[string]interface{}),
	}
	info.Ports.Discovery = int(node.UDP)
	info.Ports.Listener = int(node.TCP)

	// Gather all the running protocol infos (only once per protocol type)
	for _, proto := range srv.Protocols {
		if _, ok := info.Protocols[proto.Name]; !ok {
			nodeInfo := interface{}("unknown")
			if query := proto.NodeInfo; query != nil {
				nodeInfo = proto.NodeInfo()
			}
			info.Protocols[proto.Name] = nodeInfo
		}
	}
	return info
}

// 返回本地已经排序好的 peers
// PeersInfo returns an array of metadata objects describing connected peers.
func (srv *Server) PeersInfo() []*PeerInfo {
	// Gather all the generic and sub-protocol specific infos
	infos := make([]*PeerInfo, 0, srv.PeerCount())
	for _, peer := range srv.Peers() {
		if peer != nil {
			infos = append(infos, peer.Info())
		}
	}
	// Sort the result array alphabetically by node identifier
	for i := 0; i < len(infos); i++ {
		for j := i + 1; j < len(infos); j++ {
			if infos[i].ID > infos[j].ID {
				infos[i], infos[j] = infos[j], infos[i]
			}
		}
	}
	return infos
}
