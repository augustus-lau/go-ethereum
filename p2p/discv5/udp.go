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
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/ethereum/go-ethereum/p2p/netutil"
	"github.com/ethereum/go-ethereum/rlp"
)

const Version = 4

// Errors
var (
	errPacketTooSmall = errors.New("too small")
	errBadPrefix      = errors.New("bad prefix")
	errTimeout        = errors.New("RPC timeout")
)

// Timeouts
const (
	respTimeout = 500 * time.Millisecond
	expiration  = 20 * time.Second

	driftThreshold = 10 * time.Second // Allowed clock drift before warning user
)

// RPC request structures
type (
	ping struct {
		Version    uint
		From, To   rpcEndpoint
		Expiration uint64

		// v5
		Topics []Topic

		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// pong is the reply to ping.
	pong struct {
		// This field should mirror the UDP envelope address
		// of the ping packet, which provides a way to discover the
		// the external address (after NAT).
		To rpcEndpoint

		ReplyTok   []byte // This contains the hash of the ping packet.
		Expiration uint64 // Absolute timestamp at which the packet becomes invalid.

		// v5
		TopicHash    common.Hash
		TicketSerial uint32
		WaitPeriods  []uint32

		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// 当查询离目标节点最近的一个节点时 ，返回该结构
	// findnode is a query for nodes close to the given target.
	findnode struct {
		Target     NodeID // doesn't need to be an actual public key
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// 当查询离目标节点最近的一个节点时 ，返回该结构
	// findnode is a query for nodes close to the given target.
	findnodeHash struct {
		Target     common.Hash
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// 当有人请求我的邻居节点时，返回该结构
	// reply to findnode
	neighbors struct {
		Nodes      []rpcNode //这里保存了当前节点+要请求的节点
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	topicRegister struct {
		Topics []Topic
		Idx    uint
		Pong   []byte
	}

	topicQuery struct {
		Topic      Topic
		Expiration uint64
	}

	// reply to topicQuery
	topicNodes struct {
		Echo  common.Hash
		Nodes []rpcNode
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

var (
	versionPrefix     = []byte("temporary discovery v5")
	versionPrefixSize = len(versionPrefix)
	sigSize           = 520 / 8                     // 65位签名长度
	headSize          = versionPrefixSize + sigSize // space of packet frame data //数据包的header长度
)

// Neighbors replies are sent across multiple packets to
// stay below the 1280 byte limit. We compute the maximum number
// of entries by stuffing a packet until it grows too large.
var maxNeighbors = func() int {
	p := neighbors{Expiration: ^uint64(0)}

	//最远的节点-- 这个节点标识集群中最大的节点
	maxSizeNode := rpcNode{IP: make(net.IP, 16), UDP: ^uint16(0), TCP: ^uint16(0)}

	for n := 0; ; n++ {
		//每次循环都添加一个节点
		p.Nodes = append(p.Nodes, maxSizeNode)

		//然后对不断增大的数据进行编码，返回编码后的长度
		//由于编码后的数据是要发送给对方的，而发送的数据是与长度限制的，所以这里采用发送数据的长度来衡量 最大的邻居节点的个数
		size, _, err := rlp.EncodeToReader(p)
		if err != nil {
			// If this ever happens, it will be caught by the unit tests.
			panic("cannot encode: " + err.Error())
		}
		//headsize+datasize+ptype 不能超过1280
		if headSize+size+1 >= 1280 {
			return n
		}
	}
}()

var maxTopicNodes = func() int {
	p := topicNodes{}
	maxSizeNode := rpcNode{IP: make(net.IP, 16), UDP: ^uint16(0), TCP: ^uint16(0)}
	for n := 0; ; n++ {
		p.Nodes = append(p.Nodes, maxSizeNode)
		size, _, err := rlp.EncodeToReader(p)
		if err != nil {
			// If this ever happens, it will be caught by the unit tests.
			panic("cannot encode: " + err.Error())
		}
		if headSize+size+1 >= 1280 {
			return n
		}
	}
}()

func makeEndpoint(addr *net.UDPAddr, tcpPort uint16) rpcEndpoint {
	ip := addr.IP.To4()
	if ip == nil {
		ip = addr.IP.To16()
	}
	return rpcEndpoint{IP: ip, UDP: uint16(addr.Port), TCP: tcpPort}
}

func (e1 rpcEndpoint) equal(e2 rpcEndpoint) bool {
	return e1.UDP == e2.UDP && e1.TCP == e2.TCP && e1.IP.Equal(e2.IP)
}

func nodeFromRPC(sender *net.UDPAddr, rn rpcNode) (*Node, error) {
	if err := netutil.CheckRelayIP(sender.IP, rn.IP); err != nil {
		return nil, err
	}
	n := NewNode(rn.ID, rn.IP, rn.UDP, rn.TCP)
	err := n.validateComplete()
	return n, err
}

func nodeToRPC(n *Node) rpcNode {
	return rpcNode{ID: n.ID, IP: n.IP, UDP: n.UDP, TCP: n.TCP}
}

type ingressPacket struct {
	remoteID   NodeID
	remoteAddr *net.UDPAddr
	ev         nodeEvent
	hash       []byte      // 接收到数据后，重新计算出的该数据签名
	data       interface{} // one of the RPC structs  经过rlp反解码后的数据, 这里传递过来的是一个rpc的方法，用于反射调用
	rawData    []byte      //最原始的数据
}

type conn interface {
	ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error)
	WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error)
	Close() error
	LocalAddr() net.Addr
}

// udp implements the RPC protocol.
type udp struct {
	conn        conn
	priv        *ecdsa.PrivateKey
	ourEndpoint rpcEndpoint
	nat         nat.Interface
	net         *Network
}

// ListenUDP returns a new table that listens for UDP packets on laddr.
func ListenUDP(priv *ecdsa.PrivateKey, conn conn, realaddr *net.UDPAddr, nodeDBPath string, netrestrict *netutil.Netlist) (*Network, error) {

	//初始化传输层 udp
	transport, err := listenUDP(priv, conn, realaddr)
	if err != nil {
		return nil, err
	}
	//初始化网络层
	net, err := newNetwork(transport, priv.PublicKey, nodeDBPath, netrestrict)
	if err != nil {
		return nil, err
	}
	log.Info("UDP listener up", "net", net.tab.self)
	transport.net = net
	go transport.readLoop()
	return net, nil
}

func listenUDP(priv *ecdsa.PrivateKey, conn conn, realaddr *net.UDPAddr) (*udp, error) {
	return &udp{conn: conn, priv: priv, ourEndpoint: makeEndpoint(realaddr, uint16(realaddr.Port))}, nil
}

func (t *udp) localAddr() *net.UDPAddr {
	return t.conn.LocalAddr().(*net.UDPAddr)
}

func (t *udp) Close() {
	t.conn.Close()
}

func (t *udp) send(remote *Node, ptype nodeEvent, data interface{}) (hash []byte) {
	hash, _ = t.sendPacket(remote.ID, remote.addr(), byte(ptype), data)
	return hash
}

func (t *udp) sendPing(remote *Node, toaddr *net.UDPAddr, topics []Topic) (hash []byte) {

	// 返回发送数据包的签名---为什么要返回该数据包的签名呢，
	// 因为当对方相应的时候，会将数据包的签名再传递回来，这样就能断定，对方的相应是对那个请求的相应了。
	hash, _ = t.sendPacket(remote.ID, toaddr, byte(pingPacket), ping{
		Version:    Version,
		From:       t.ourEndpoint,
		To:         makeEndpoint(toaddr, uint16(toaddr.Port)), // TODO: maybe use known TCP port from DB
		Expiration: uint64(time.Now().Add(expiration).Unix()),
		Topics:     topics,
	})
	return hash
}

func (t *udp) sendFindnode(remote *Node, target NodeID) {
	t.sendPacket(remote.ID, remote.addr(), byte(findnodePacket), findnode{
		Target:     target,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
}

//向远程节点remote发送消息，让远程节点去在其邻居节点中查找node
func (t *udp) sendNeighbours(remote *Node, results []*Node) {
	// Send neighbors in chunks with at most maxNeighbors per packet
	// to stay below the 1280 byte limit.

	//初始化该请求的超时时间 = 当前时间+过期时间20s
	p := neighbors{Expiration: uint64(time.Now().Add(expiration).Unix())}

	//遍历所有的节点
	for i, result := range results {

		//将当前节点和要请求的节点放在一起
		p.Nodes = append(p.Nodes, nodeToRPC(result))

		//maxNeighbors是根据发送的数据长度来衡量要邻居节点的个数的
		//如果发送的数据已经够了，或者结果集遍历完了，则将这些节点发送给remote节点
		if len(p.Nodes) == maxNeighbors || i == len(results)-1 {
			t.sendPacket(remote.ID, remote.addr(), byte(neighborsPacket), p)

			//发送完成后，将清空
			p.Nodes = p.Nodes[:0]
		}
	}
}

func (t *udp) sendFindnodeHash(remote *Node, target common.Hash) {
	t.sendPacket(remote.ID, remote.addr(), byte(findnodeHashPacket), findnodeHash{
		Target:     target,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
}

func (t *udp) sendTopicRegister(remote *Node, topics []Topic, idx int, pong []byte) {
	t.sendPacket(remote.ID, remote.addr(), byte(topicRegisterPacket), topicRegister{
		Topics: topics,
		Idx:    uint(idx),
		Pong:   pong,
	})
}

func (t *udp) sendTopicNodes(remote *Node, queryHash common.Hash, nodes []*Node) {
	p := topicNodes{Echo: queryHash}
	var sent bool
	for _, result := range nodes {
		if result.IP.Equal(t.net.tab.self.IP) || netutil.CheckRelayIP(remote.IP, result.IP) == nil {
			p.Nodes = append(p.Nodes, nodeToRPC(result))
		}
		if len(p.Nodes) == maxTopicNodes {
			t.sendPacket(remote.ID, remote.addr(), byte(topicNodesPacket), p)
			p.Nodes = p.Nodes[:0]
			sent = true
		}
	}
	if !sent || len(p.Nodes) > 0 {
		t.sendPacket(remote.ID, remote.addr(), byte(topicNodesPacket), p)
	}
}

func (t *udp) sendPacket(toid NodeID, toaddr *net.UDPAddr, ptype byte, req interface{}) (hash []byte, err error) {

	//返回数据包packet， 和数据包的签名
	//fmt.Println("sendPacket", nodeEvent(ptype), toaddr.String(), toid.String())
	packet, hash, err := encodePacket(t.priv, ptype, req)
	if err != nil {
		//fmt.Println(err)
		return hash, err
	}
	log.Trace(fmt.Sprintf(">>> %v to %x@%v", nodeEvent(ptype), toid[:8], toaddr))

	//发送该数据包，
	if _, err = t.conn.WriteToUDP(packet, toaddr); err != nil {
		log.Trace(fmt.Sprint("UDP send failed:", err))
	}
	//返回该数据包的签名--应该本地留存
	//fmt.Println(err)
	return hash, err
}

// zeroed padding space for encodePacket.
var headSpace = make([]byte, headSize)

/**
 * @param priv  ec算法得出的私钥
 * @param ptype 请求的时间类型
 * @req         请求的参数
 * 该方法主要是 在发送请求时，对请求进行加密 和编码，并签名
 * 加密采用了非对称加密，编码采用rlp编码规则。该编码规则是可以改的，比如我们直接用json来编码也是可以的
 */
func encodePacket(priv *ecdsa.PrivateKey, ptype byte, req interface{}) (p, hash []byte, err error) {
	b := new(bytes.Buffer)

	//这里是在头部 写入了一个空的byte数组，该数组的大小是 versionPrefixSize + sigSize
	b.Write(headSpace)
	b.WriteByte(ptype)

	//采用rlp对数据进行编码(或者改为json)
	if err := rlp.Encode(b, req); err != nil {
		log.Error(fmt.Sprint("error encoding packet:", err))
		return nil, nil, err
	}
	// 生成packet的 字节数组
	packet := b.Bytes()

	// 对header后的数据 用私钥签名--为了防篡改，注意 只是为了防篡改
	// 这里的原理是，对data+ptype进行数字签名
	// 然后对生成的摘要指纹 进行加密 --- 注意 这里是对摘要指纹进行加密
	sig, err := crypto.Sign(crypto.Keccak256(packet[headSize:]), priv)
	if err != nil {
		log.Error(fmt.Sprint("could not sign packet:", err))
		return nil, nil, err
	}

	//之前在头部写了一个空的数组，此时将版本号填充到头部
	copy(packet, versionPrefix)
	//将空数组剩余的空缺部分 用sig填充
	copy(packet[versionPrefixSize:], sig)

	//然后对 剩余的部分在做一次签名，该签名代表了packet整体的数据，防止篡改
	hash = crypto.Keccak256(packet[versionPrefixSize:])

	//所以
	return packet, hash, nil
}

/* 单线程启动后，监听udp接口的数据，这里是用一个线程来单独处理的 */
// readLoop runs in its own goroutine. it injects ingress UDP packets
// into the network loop.
func (t *udp) readLoop() {
	defer t.conn.Close()
	// Discovery packets are defined to be no larger than 1280 bytes.
	// Packets larger than this size will be cut at the end and treated
	// as invalid because their hash won't match.
	buf := make([]byte, 1280)
	for {
		nbytes, from, err := t.conn.ReadFromUDP(buf)
		if netutil.IsTemporaryError(err) {
			// Ignore temporary read errors.
			log.Debug(fmt.Sprintf("Temporary read error: %v", err))
			continue
		} else if err != nil {
			// Shut down the loop for permament errors.
			log.Debug(fmt.Sprintf("Read error: %v", err))
			return
		}
		t.handlePacket(from, buf[:nbytes])
	}
}

func (t *udp) handlePacket(from *net.UDPAddr, buf []byte) error {
	pkt := ingressPacket{remoteAddr: from}
	if err := decodePacket(buf, &pkt); err != nil {
		log.Debug(fmt.Sprintf("Bad packet from %v: %v", from, err))
		//fmt.Println("bad packet", err)
		return err
	}
	t.net.reqReadPacket(pkt)
	return nil
}

func decodePacket(buffer []byte, pkt *ingressPacket) error {

	// headsize = versionsize + sigsize + ptypesize,如果过小，则异常
	if len(buffer) < headSize+1 {
		return errPacketTooSmall
	}
	buf := make([]byte, len(buffer))
	//将接受到的数据copy到缓冲中
	copy(buf, buffer)

	//获取到版本号，经过私钥加密的签名指纹，和数据
	prefix, sig, sigdata := buf[:versionPrefixSize], buf[versionPrefixSize:headSize], buf[headSize:]

	//首先判断版本号是否相同
	if !bytes.Equal(prefix, versionPrefix) {
		return errBadPrefix
	}

	// 首先，crypto.Keccak256(buf[headSize:])计算出 数据的未加密签名
	// 其次，根据未加密签名 和 已经经过私钥加密的签名sig，能算出来公钥----- 这一点ecc非对称加密算法是如何做到的？ 这个我很不理解
	// 最后，这里要理解nodeid是如何生成的，节点的nodeid是用公钥 在头部加了一位 随机数而形成的
	fromID, err := recoverNodeID(crypto.Keccak256(buf[headSize:]), sig)

	if err != nil {
		return err
	}

	//接收到的原始数据
	pkt.rawData = buf

	// 再次计算出 接收到数据的 未加密签名
	pkt.hash = crypto.Keccak256(buf[versionPrefixSize:])
	pkt.remoteID = fromID

	//计算出节点的相应类型
	switch pkt.ev = nodeEvent(sigdata[0]); pkt.ev {
	case pingPacket:
		pkt.data = new(ping)
	case pongPacket:
		pkt.data = new(pong)
	case findnodePacket:
		pkt.data = new(findnode)
	case neighborsPacket:
		pkt.data = new(neighbors)
	case findnodeHashPacket:
		pkt.data = new(findnodeHash)
	case topicRegisterPacket:
		pkt.data = new(topicRegister)
	case topicQueryPacket:
		pkt.data = new(topicQuery)
	case topicNodesPacket:
		pkt.data = new(topicNodes)
	default:
		return fmt.Errorf("unknown packet type: %d", sigdata[0])
	}

	//将rlp数据解码出来-- 并发到pkt的data属性中
	s := rlp.NewStream(bytes.NewReader(sigdata[1:]), 0)
	err = s.Decode(pkt.data)
	return err
}
