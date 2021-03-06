// Copyright 2015 The go-ethereum Authors
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

package discover

import (
	"bytes"
	"container/list"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/ethereum/go-ethereum/p2p/netutil"
	"github.com/ethereum/go-ethereum/rlp"
)

const Version = 4

// Errors
var (
	errPacketTooSmall   = errors.New("too small")
	errBadHash          = errors.New("bad hash")
	errExpired          = errors.New("expired")
	errUnsolicitedReply = errors.New("unsolicited reply")
	errUnknownNode      = errors.New("unknown node")
	errTimeout          = errors.New("RPC timeout")
	errClockWarp        = errors.New("reply deadline too far in the future")
	errClosed           = errors.New("socket closed")
)

// Timeouts
const (
	respTimeout = 500 * time.Millisecond
	expiration  = 20 * time.Second

	ntpFailureThreshold = 32               // Continuous timeouts after which to check NTP
	ntpWarningCooldown  = 10 * time.Minute // Minimum amount of time to pass before repeating NTP warning
	driftThreshold      = 10 * time.Second // Allowed clock drift before warning user
)

// RPC packet types
const (
	pingPacket = iota + 1 // zero is 'reserved'  //初始化为1  iota 是初始化零标识符
	pongPacket
	findnodePacket
	neighborsPacket
)

// RPC request structures
type (
	ping struct {
		Version    uint        //当前的udp的版本号
		From, To   rpcEndpoint // 来源 去处
		Expiration uint64      //ping的过期时间
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// pong is the reply to ping.
	pong struct {
		// This field should mirror the UDP envelope address
		// of the ping packet, which provides a way to discover the
		// the external address (after NAT).
		To rpcEndpoint //响应给谁

		//由于ping /pong 必须一一对应，故这里 包含了ping过来是 数据的 hash值
		ReplyTok   []byte // This contains the hash of the ping packet.
		Expiration uint64 // Absolute timestamp at which the packet becomes invalid.
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// findnode is a query for nodes close to the given target.
	findnode struct {
		Target     NodeID // doesn't need to be an actual public key
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// reply to findnode
	neighbors struct {
		Nodes      []rpcNode
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	rpcNode struct {
		IP  net.IP // len 4 for IPv4 or 16 for IPv6
		UDP uint16 // for discovery protocol
		TCP uint16 // for RLPx protocol
		ID  NodeID
	}

	rpcEndpoint struct {
		IP  net.IP // len 4 for IPv4 or 16 for IPv6
		UDP uint16 // for discovery protocol
		TCP uint16 // for RLPx protocol
	}
)

func makeEndpoint(addr *net.UDPAddr, tcpPort uint16) rpcEndpoint {
	ip := addr.IP.To4()
	if ip == nil {
		ip = addr.IP.To16()
	}
	return rpcEndpoint{IP: ip, UDP: uint16(addr.Port), TCP: tcpPort}
}

func (t *udp) nodeFromRPC(sender *net.UDPAddr, rn rpcNode) (*Node, error) {
	if rn.UDP <= 1024 {
		return nil, errors.New("low port")
	}
	if err := netutil.CheckRelayIP(sender.IP, rn.IP); err != nil {
		return nil, err
	}
	if t.netrestrict != nil && !t.netrestrict.Contains(rn.IP) {
		return nil, errors.New("not contained in netrestrict whitelist")
	}
	n := NewNode(rn.ID, rn.IP, rn.UDP, rn.TCP)
	err := n.validateComplete()
	return n, err
}

func nodeToRPC(n *Node) rpcNode {
	return rpcNode{ID: n.ID, IP: n.IP, UDP: n.UDP, TCP: n.TCP}
}

type packet interface {
	handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error
	name() string
}

type conn interface {
	ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error)
	WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error)
	Close() error
	LocalAddr() net.Addr
}

// udp为什么实现rpc协议
// udp implements the RPC protocol.
type udp struct {
	conn        conn
	netrestrict *netutil.Netlist
	priv        *ecdsa.PrivateKey
	ourEndpoint rpcEndpoint

	addpending chan *pending
	gotreply   chan reply //

	closing chan struct{} // 关闭通道
	nat     nat.Interface //nat网络

	*Table
}

// pending represents a pending reply.
//
// some implementations of the protocol wish to send more than one
// reply packet to findnode. in general, any neighbors packet cannot
// be matched up with a specific findnode packet.
//
// our implementation handles this by storing a callback function for
// each pending reply. incoming packets from a node are dispatched
// to all the callback functions for that node.
type pending struct {
	// these fields must match in the reply.
	from  NodeID //来源节点的id
	ptype byte   //数据包的类型

	// time when the request must complete
	deadline time.Time //超时时间点

	// callback is called when a matching reply arrives. if it returns
	// true, the callback is removed from the pending reply queue.
	// if it returns false, the reply is considered incomplete and
	// the callback will be invoked again for the next matching reply.
	callback func(resp interface{}) (done bool) // 如果udp的请求需要回复，这调用该接口回复

	// errc receives nil when the callback indicates completion or an
	// error if no further reply is received within the timeout.
	errc chan<- error
}

type reply struct {
	from  NodeID      //来源
	ptype byte        //响应类型
	data  interface{} //数据
	// loop indicates whether there was
	// a matching request by sending on this channel.
	matched chan<- bool
}

//当对方发过来一个只读包时(不需要回复的)，就封装成ReadPacket
// ReadPacket is sent to the unhandled channel when it could not be processed
type ReadPacket struct {
	Data []byte
	Addr *net.UDPAddr
}

// Config holds Table-related settings.
type Config struct {
	// These settings are required and configure the UDP listener:
	PrivateKey *ecdsa.PrivateKey

	// These settings are optional:
	AnnounceAddr *net.UDPAddr     // local address announced in the DHT
	NodeDBPath   string           // if set, the node database is stored at this filesystem location
	NetRestrict  *netutil.Netlist // network whitelist  //黑名单
	Bootnodes    []*Node          // list of bootstrap nodes  //守护节点

	//无需回复通道，为什么要放到路由配置中，，难道只有路由表信息的请求才会用该通道的数据么
	Unhandled chan<- ReadPacket // unhandled packets are sent on this channel
}

// ListenUDP returns a new table that listens for UDP packets on laddr.
func ListenUDP(c conn, cfg Config) (*Table, error) {
	tab, _, err := newUDP(c, cfg)
	if err != nil {
		return nil, err
	}
	log.Info("UDP listener up", "self", tab.self)
	return tab, nil
}

// 对udp进行封装， 原有的udp句柄只是一个读取数据的对象
// 这里对udp封装，主要是增加udp的 控制并发的能力 和 加密方式，采用通道的方式来解决
func newUDP(c conn, cfg Config) (*Table, *udp, error) {
	udp := &udp{
		conn:        c,
		priv:        cfg.PrivateKey,
		netrestrict: cfg.NetRestrict,
		closing:     make(chan struct{}), //接受udp服务停止信号量
		gotreply:    make(chan reply),    //保存 正在等待别人给我的回复
		addpending:  make(chan *pending), //当向外发送了消息，但是尚未接收到回复的 请求
	}
	realaddr := c.LocalAddr().(*net.UDPAddr)
	if cfg.AnnounceAddr != nil {
		realaddr = cfg.AnnounceAddr
	}
	// TODO: separate TCP port  //生成udp的rpc结构体
	udp.ourEndpoint = makeEndpoint(realaddr, uint16(realaddr.Port))

	tab, err := newTable(udp, PubkeyID(&cfg.PrivateKey.PublicKey), realaddr, cfg.NodeDBPath, cfg.Bootnodes)
	if err != nil {
		return nil, nil, err
	}
	udp.Table = tab

	// 起线程 不断刷新路由表
	go udp.loop()

	// 起协程 接受udp 所有请求 ----- 这里就是udp接受所有请求的开始
	// 将udp接受到的数据 全部放入到了Unhandled通道中(无需回复通道)
	go udp.readLoop(cfg.Unhandled)
	return udp.Table, udp, nil
}

func (t *udp) close() {
	close(t.closing)
	t.conn.Close()
	// TODO: wait for the loops to end.
}

// ping sends a ping message to the given node and waits for a reply.
func (t *udp) ping(toid NodeID, toaddr *net.UDPAddr) error {
	req := &ping{
		Version:    Version,
		From:       t.ourEndpoint,
		To:         makeEndpoint(toaddr, 0), // TODO: maybe use known TCP port from DB
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	}
	packet, hash, err := encodePacket(t.priv, pingPacket, req)
	if err != nil {
		return err
	}
	errc := t.pending(toid, pongPacket, func(p interface{}) bool {
		return bytes.Equal(p.(*pong).ReplyTok, hash)
	})
	t.write(toaddr, req.name(), packet)
	return <-errc
}

func (t *udp) waitping(from NodeID) error {
	return <-t.pending(from, pingPacket, func(interface{}) bool { return true })
}

// findnode sends a findnode request to the given node and waits until
// the node has sent up to k neighbors.
func (t *udp) findnode(toid NodeID, toaddr *net.UDPAddr, target NodeID) ([]*Node, error) {
	nodes := make([]*Node, 0, bucketSize)
	nreceived := 0
	errc := t.pending(toid, neighborsPacket, func(r interface{}) bool {
		reply := r.(*neighbors)
		for _, rn := range reply.Nodes {
			nreceived++
			n, err := t.nodeFromRPC(toaddr, rn)
			if err != nil {
				log.Trace("Invalid neighbor node received", "ip", rn.IP, "addr", toaddr, "err", err)
				continue
			}
			nodes = append(nodes, n)
		}
		return nreceived >= bucketSize
	})
	t.send(toaddr, findnodePacket, &findnode{
		Target:     target,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	err := <-errc
	return nodes, err
}

// pending adds a reply callback to the pending reply queue.
// see the documentation of type pending for a detailed explanation.
func (t *udp) pending(id NodeID, ptype byte, callback func(interface{}) bool) <-chan error {
	ch := make(chan error, 1)
	p := &pending{from: id, ptype: ptype, callback: callback, errc: ch}
	select {
	case t.addpending <- p:
		// loop will handle it
	case <-t.closing:
		ch <- errClosed
	}
	return ch
}

//处理从nodeid 过来的回复消息---阻塞
func (t *udp) handleReply(from NodeID, ptype byte, req packet) bool {
	matched := make(chan bool, 1)

	select {
	//首先构造一个回复的结构体，并放入到reply通道中
	case t.gotreply <- reply{from, ptype, req, matched}:
		// loop will handle it

		//阻塞，直到返回成功。如果该通道中一直为空，则一直阻塞。返回false,就一定需要将该节点加入到本地路由表中
		return <-matched
	case <-t.closing:
		return false
	}
}

// loop runs in its own goroutine. it keeps track of
// the refresh timer and the pending reply queue.
func (t *udp) loop() {

	// 线程中的局部变量
	var (
		plist = list.New() //线程本地缓存

		timeout      = time.NewTimer(0) // 超时校验调度器
		nextTimeout  *pending           // head of plist when timeout was last reset // 最新的一个即将超时的数据
		contTimeouts = 0                // number of continuous timeouts to do NTP checks  已经超时的数据个数
		ntpWarnTime  = time.Unix(0, 0)  // 多个节点间的时间差异 大于该值是发出警告
	)

	// 忽略第一个超时数据
	<-timeout.C // ignore first timeout
	defer timeout.Stop()

	resetTimeout := func() {
		if plist.Front() == nil || nextTimeout == plist.Front().Value {
			return
		}
		// Start the timer so it fires when the next pending reply has expired.
		now := time.Now()
		for el := plist.Front(); el != nil; el = el.Next() {
			nextTimeout = el.Value.(*pending)
			if dist := nextTimeout.deadline.Sub(now); dist < 2*respTimeout {
				timeout.Reset(dist)
				return
			}

			//删除已经超时的数据
			// Remove pending replies whose deadline is too far in the
			// future. These can occur if the system clock jumped
			// backwards after the deadline was assigned.
			nextTimeout.errc <- errClockWarp
			plist.Remove(el)
		}
		nextTimeout = nil
		timeout.Stop()
	}

	//开始循环
	for {

		// 每次循环重置时间
		resetTimeout()

		// 选择一个通道来相应数据，如果没有接收到消息 或者没有通道匹配 则退出
		select {
		case <-t.closing:

			// 向所有节点的关闭通道中发送一个消息，关闭连接
			for el := plist.Front(); el != nil; el = el.Next() {
				el.Value.(*pending).errc <- errClosed
			}
			return

		// 如果发起了一个udp请求，则添加到pending中
		case p := <-t.addpending:
			p.deadline = time.Now().Add(respTimeout)
			plist.PushBack(p)

		// gotreply，不是要给别人回复，而是正在等待 别人给我的答复
		// 如果接受到了回复请求，则遍历所有的节点，-- 如果匹配到，确实是我正在等待的回复，则返回匹配成功。
		case r := <-t.gotreply:
			var matched bool

			//plist 中放的是 本机主动发起的ping,
			// 如果在plist中找到了对方节点的信息，说明本机是知道对方的地址信息的，所以返回true
			// 如果在plist中没有找到对方节点的信息，说明这个回复 不是由对方节点主动发起的，而本地不一定存储了对方节点的信息，返回false
			// 所以返回false 代表本机不一定知道对方节点的信息，如果返回false,就需要将该节点加入到本地路由表中
			for el := plist.Front(); el != nil; el = el.Next() {
				p := el.Value.(*pending)
				if p.from == r.from && p.ptype == r.ptype {
					matched = true
					// Remove the matcher if its callback indicates
					// that all replies have been received. This is
					// required for packet types that expect multiple
					// reply packets.
					if p.callback(r.data) {
						p.errc <- nil
						plist.Remove(el)
					}
					// Reset the continuous timeout counter (time drift detection)
					contTimeouts = 0
				}
			}

			// 如果不是本机主动发起的ping，这里就 返回未匹配到，代表不需要加入到路由表中
			// 所有只有主动发起的ping才会加入到路由表中
			r.matched <- matched

		//如果超时
		case now := <-timeout.C:
			nextTimeout = nil

			// Notify and remove callbacks whose deadline is in the past.
			for el := plist.Front(); el != nil; el = el.Next() {
				p := el.Value.(*pending)
				if now.After(p.deadline) || now.Equal(p.deadline) {
					p.errc <- errTimeout
					plist.Remove(el)
					contTimeouts++
				}
			}
			// 如果超时个数 太多，有可能是节点间的时间不一致，起线程 同步服务期间的时间
			// If we've accumulated too many timeouts, do an NTP time sync check
			if contTimeouts > ntpFailureThreshold {
				if time.Since(ntpWarnTime) >= ntpWarningCooldown {
					ntpWarnTime = time.Now()
					go checkClockDrift()
				}
				contTimeouts = 0
			}
		}
	}
}

const (
	//mac地址大小占32个字节大小----- 这个保存packet的整个签名
	macSize = 256 / 8
	//签名大小占65个字节大小
	sigSize = 520 / 8

	//头的大小一共占  32+65 = 97个字节大小
	headSize = macSize + sigSize // space of packet frame data
)

var (
	headSpace = make([]byte, headSize)

	// Neighbors replies are sent across multiple packets to
	// stay below the 1280 byte limit. We compute the maximum number
	// of entries by stuffing a packet until it grows too large.
	maxNeighbors int
)

func init() {
	p := neighbors{Expiration: ^uint64(0)}
	maxSizeNode := rpcNode{IP: make(net.IP, 16), UDP: ^uint16(0), TCP: ^uint16(0)}
	for n := 0; ; n++ {
		p.Nodes = append(p.Nodes, maxSizeNode)
		size, _, err := rlp.EncodeToReader(p)
		if err != nil {
			// If this ever happens, it will be caught by the unit tests.
			panic("cannot encode: " + err.Error())
		}
		if headSize+size+1 >= 1280 {
			maxNeighbors = n
			break
		}
	}
}

/**
 * @param toaddr 目标地址
 * @param ptype  消息类型(只有四种)
 * @param req    数据包
 */
func (t *udp) send(toaddr *net.UDPAddr, ptype byte, req packet) ([]byte, error) {
	packet, hash, err := encodePacket(t.priv, ptype, req)
	if err != nil {
		return hash, err
	}
	return hash, t.write(toaddr, req.name(), packet)
}

func (t *udp) write(toaddr *net.UDPAddr, what string, packet []byte) error {
	_, err := t.conn.WriteToUDP(packet, toaddr)
	log.Trace(">> "+what, "addr", toaddr, "err", err)
	return err
}

/**
 * 对要发送的数据包进行编码和加密，，
 * 1、这里不对原始数据进行加密，只对原始数据进行编码。估计是因为原始数据暴露出来其实不重要
 * 2、udp的数据 只做了防篡改的签名加密操作
 * @param priv  私钥
 * @param ptype 类型
 * @param req   传输的数据
 *
 */
func encodePacket(priv *ecdsa.PrivateKey, ptype byte, req interface{}) (packet, hash []byte, err error) {

	b := new(bytes.Buffer)

	// 写入headspaced个空数组数据
	b.Write(headSpace)
	//写入一个字节的事件类型
	b.WriteByte(ptype)
	//首先对数据进行编码-- 类似json，采用rlp格式序列化数据
	// 采用rlp对数据编码 并保存到b中
	if err := rlp.Encode(b, req); err != nil {
		log.Error("Can't encode discv4 packet", "err", err)
		return nil, nil, err
	}
	// header + ptype
	packet = b.Bytes()

	// 首先对header后的所有数据做sha3的hash
	// 然后采用私钥对 该hash加密 --- 注意这里是对hash值 加密得到 签名
	sig, err := crypto.Sign(crypto.Keccak256(packet[headSize:]), priv)

	if err != nil {
		log.Error("Can't sign discv4 packet", "err", err)
		return nil, nil, err
	}

	// 将签名写入  目前packet中  header + ptype +sig(签名)
	copy(packet[macSize:], sig)

	// add the hash to the front. Note: this doesn't protect the
	// packet in any way. Our public key will be part of this hash in
	// The future.
	// 然后在对 sig+ptype+data 进行keccak做签名 --256
	// 这里的mac是指h-mac 签名算法
	hash = crypto.Keccak256(packet[macSize:])

	//将该签名写入到packet的前几位
	copy(packet, hash)
	return packet, hash, nil
}

// readLoop runs in its own goroutine. it handles incoming UDP packets.
func (t *udp) readLoop(unhandled chan<- ReadPacket) {
	defer t.conn.Close()
	if unhandled != nil {
		defer close(unhandled)
	}
	// Discovery packets are defined to be no larger than 1280 bytes.
	// Packets larger than this size will be cut at the end and treated
	// as invalid because their hash won't match.

	//定义一个1280大小的缓冲,默认发现机制不允许超过1280
	//如果超过，则认为无效
	buf := make([]byte, 1280)

	//无线循环读取-- 这里采用的是 阻塞模型- 并且是一个线程 一个个处理接受到的请求
	for {
		//数据大小，来源， 保存到buf中
		nbytes, from, err := t.conn.ReadFromUDP(buf)
		if netutil.IsTemporaryError(err) {
			// Ignore temporary read errors.
			log.Debug("Temporary UDP read error", "err", err)
			continue
		} else if err != nil {
			// Shut down the loop for permament errors.
			log.Debug("UDP read error", "err", err)
			return
		}
		//将数据封装成 系统可以处理的数据结构
		if t.handlePacket(from, buf[:nbytes]) != nil && unhandled != nil {
			select {
			case unhandled <- ReadPacket{buf[:nbytes], from}:
			default:
			}
		}
	}
}

/**
 * @param from   udp接受到的数据来源ip-port
 * @param from   udp接受到的数据
 * 接受到消息后，处理该消息
 */
func (t *udp) handlePacket(from *net.UDPAddr, buf []byte) error {

	// 对数据进行解码，解析出 数据包，来源节点的id, hash签名
	packet, fromID, hash, err := decodePacket(buf)
	if err != nil {
		log.Debug("Bad discv4 packet", "addr", from, "err", err)
		return err
	}

	err = packet.handle(t, from, fromID, hash)
	log.Trace("<< "+packet.name(), "addr", from, "err", err)
	return err
}

//对接收到的数据进行解码
func decodePacket(buf []byte) (packet, NodeID, []byte, error) {

	//校验头的大小 (header+type 尺寸)
	if len(buf) < headSize+1 {
		return nil, NodeID{}, nil, errPacketTooSmall
	}

	//签名，sig，和签名的数据---- ~32位     32~65位   65位~~
	hash, sig, sigdata := buf[:macSize], buf[macSize:headSize], buf[headSize:]

	//sha-3 对 sig+sigdata hash ，与之前的hash签名 比对，如果不同，则被篡改过
	shouldhash := crypto.Keccak256(buf[macSize:])
	if !bytes.Equal(hash, shouldhash) {
		return nil, NodeID{}, nil, errBadHash
	}

	//从数据中解析出来源及其的nodeid
	fromID, err := recoverNodeID(crypto.Keccak256(buf[headSize:]), sig)

	if err != nil {
		return nil, NodeID{}, hash, err
	}
	var req packet

	// 从数据中国解析出请求类型，根据不同的类型，生成不同的数据包
	switch ptype := sigdata[0]; ptype {
	case pingPacket:
		req = new(ping)
	case pongPacket:
		req = new(pong)
	case findnodePacket:
		req = new(findnode)
	case neighborsPacket:
		req = new(neighbors)
	default:
		return nil, fromID, hash, fmt.Errorf("unknown type: %d", ptype)
	}

	//创建一个数据流
	s := rlp.NewStream(bytes.NewReader(sigdata[1:]), 0)

	//用创建的数据流读入传递过来的数据，然后对数据进行解密
	//这里的解密规则 采用了rlp协议来加密解密数据的
	err = s.Decode(req)
	return req, fromID, hash, err
}

//如果接受到的消息类型是ping，则调用该方法处理该消息
func (req *ping) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {

	//校验该消息是否过期
	if expired(req.Expiration) {
		return errExpired
	}

	//发送一个pong包
	t.send(from, pongPacket, &pong{
		To:         makeEndpoint(from, req.From.TCP),
		ReplyTok:   mac,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})

	//阻塞 --- 等待对方回复
	// 这里是根据回复来判断是否需要加入到本地路由表，
	// -- 这里返回一定是false,因为是主动连接本机，而本机中不一定存了对方的信息，所以一定要加入到本地表
	if !t.handleReply(fromID, pingPacket, req) {
		// Note: we're ignoring the provided IP address right now

		//起一个县城，将该节点加入到路由表中
		go t.bond(true, fromID, from, req.From.TCP)
	}
	return nil
}

func (req *ping) name() string { return "PING/v4" }

func (req *pong) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	if expired(req.Expiration) {
		return errExpired
	}
	if !t.handleReply(fromID, pongPacket, req) {
		return errUnsolicitedReply
	}
	return nil
}

func (req *pong) name() string { return "PONG/v4" }

func (req *findnode) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	if expired(req.Expiration) {
		return errExpired
	}
	if !t.db.hasBond(fromID) {
		// No bond exists, we don't process the packet. This prevents
		// an attack vector where the discovery protocol could be used
		// to amplify traffic in a DDOS attack. A malicious actor
		// would send a findnode request with the IP address and UDP
		// port of the target as the source address. The recipient of
		// the findnode packet would then send a neighbors packet
		// (which is a much bigger packet than findnode) to the victim.
		return errUnknownNode
	}
	target := crypto.Keccak256Hash(req.Target[:])
	t.mutex.Lock()
	closest := t.closest(target, bucketSize).entries
	t.mutex.Unlock()

	p := neighbors{Expiration: uint64(time.Now().Add(expiration).Unix())}
	var sent bool
	// Send neighbors in chunks with at most maxNeighbors per packet
	// to stay below the 1280 byte limit.
	for _, n := range closest {
		if netutil.CheckRelayIP(from.IP, n.IP) == nil {
			p.Nodes = append(p.Nodes, nodeToRPC(n))
		}
		if len(p.Nodes) == maxNeighbors {
			t.send(from, neighborsPacket, &p)
			p.Nodes = p.Nodes[:0]
			sent = true
		}
	}
	if len(p.Nodes) > 0 || !sent {
		t.send(from, neighborsPacket, &p)
	}
	return nil
}

func (req *findnode) name() string { return "FINDNODE/v4" }

func (req *neighbors) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
	if expired(req.Expiration) {
		return errExpired
	}
	if !t.handleReply(fromID, neighborsPacket, req) {
		return errUnsolicitedReply
	}
	return nil
}

func (req *neighbors) name() string { return "NEIGHBORS/v4" }

func expired(ts uint64) bool {
	return time.Unix(int64(ts), 0).Before(time.Now())
}
