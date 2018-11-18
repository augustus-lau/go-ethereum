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

package p2p

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	mrand "math/rand"
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/golang/snappy"
)

// RLP 编码/解码协议
// RLPX 升级版
// 这里要理解 为什么用rlp-x协议， 该协议有哪些优点
// RLP 编码协议，就是葱粉利用第一个字节的存储空间，将0x7f以后的值赋予新的含义，
// 以往我们见到的编码方式主要是对指定长度字节进行编码，比如Unicode等，
// 在处理这些编码时一般按照指定长度进行拆分解码，最大的弊端是传统编码无法表现一个结构
// RLP最大的优点是在充分利用字节的情况下，同时支持列表结构，也就是说可以很轻易的利用RLP存储一个树状结构
const (
	// 取反全是1，右移8位， 高8位变为0
	maxUint24 = ^uint32(0) >> 8

	sskLen = 16 // ecies.MaxSharedKeyLength(pubKey) / 2  --校验密钥是否和算法是否匹配，只有都符合条件了才能用于加密
	sigLen = 65 // elliptic S256               椭圆加密算法签名长度
	pubLen = 64 // 512 bit pubkey in uncompressed representation without format byte  公钥长度 2^64
	shaLen = 32 // hash length (for nonce etc) hash值长度 nonce随机数，发送时使用。目的是防止重放攻击

	authMsgLen  = sigLen + shaLen + pubLen + shaLen + 1 //授权信息的长度
	authRespLen = pubLen + shaLen + 1                   //授权响应的长度

	eciesOverhead = 65 /* pubkey */ + 16 /* IV */ + 32 /* MAC */

	encAuthMsgLen  = authMsgLen + eciesOverhead  // size of encrypted pre-EIP-8 initiator handshake
	encAuthRespLen = authRespLen + eciesOverhead // size of encrypted pre-EIP-8 handshake reply

	// total timeout for encryption handshake and protocol
	// handshake in both directions.
	handshakeTimeout = 5 * time.Second //握手超时

	// This is the timeout for sending the disconnect reason.
	// This is shorter than the usual timeout because we don't want
	// to wait if the connection is known to be bad anyway.
	discWriteTimeout = 1 * time.Second //断开了解超时时间
)

// errPlainMessageTooLarge is returned if a decompressed message length exceeds
// the allowed 24 bits (i.e. length >= 16MB).
var errPlainMessageTooLarge = errors.New("message length >= 16MB")

// rlpx is the transport protocol used by actual (non-test) connections.
// It wraps the frame encoder with locks and read/write deadlines.
type rlpx struct {
	fd       net.Conn     //封装的连接
	rmu, wmu sync.Mutex   //读取、写入全局锁
	rw       *rlpxFrameRW //输入输出流
}

func newRLPX(fd net.Conn) transport {

	// 连接时长
	fd.SetDeadline(time.Now().Add(handshakeTimeout))
	return &rlpx{fd: fd}
}

func (t *rlpx) ReadMsg() (Msg, error) {
	t.rmu.Lock()
	defer t.rmu.Unlock()
	t.fd.SetReadDeadline(time.Now().Add(frameReadTimeout))
	return t.rw.ReadMsg()
}

func (t *rlpx) WriteMsg(msg Msg) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	t.fd.SetWriteDeadline(time.Now().Add(frameWriteTimeout))
	return t.rw.WriteMsg(msg)
}

func (t *rlpx) close(err error) {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	// Tell the remote end why we're disconnecting if possible.
	if t.rw != nil {
		if r, ok := err.(DiscReason); ok && r != DiscNetworkError {
			// rlpx tries to send DiscReason to disconnected peer
			// if the connection is net.Pipe (in-memory simulation)
			// it hangs forever, since net.Pipe does not implement
			// a write deadline. Because of this only try to send
			// the disconnect reason message if there is no error.
			if err := t.fd.SetWriteDeadline(time.Now().Add(discWriteTimeout)); err == nil {
				SendItems(t.rw, discMsg, r)
			}
		}
	}
	t.fd.Close()
}

/**
 * 加密协商通道已经建立完成，开始处理协议握手
 * @param our 发送方的握手协议
 * @param their  接收方的握手协议
 * 加密信道已经创建完毕。我们看到这里只是约定了是否使用Snappy加密然后就退出了
 */
func (t *rlpx) doProtoHandshake(our *protoHandshake) (their *protoHandshake, err error) {
	// Writing our handshake happens concurrently, we prefer
	// returning the handshake read error. If the remote side
	// disconnects us early with a valid reason, we should return it
	// as the error so it can be tracked elsewhere.
	werr := make(chan error, 1)
	// handshakeMsg = 0x00,将本机支持的协议发送给对方。告诉对方我采用的协议以及协议的版本
	go func() { werr <- Send(t.rw, handshakeMsg, our) }()

	/* 接受remote节点的 协议握手响应包，their表示remote节点支持的协议 */
	if their, err = readProtocolHandshake(t.rw, our); err != nil {
		<-werr // make sure the write terminates too
		return nil, err
	}
	if err := <-werr; err != nil {
		return nil, fmt.Errorf("write error: %v", err)
	}
	/* 是否支持采用snappy压缩方式*/
	// If the protocol version supports Snappy encoding, upgrade immediately
	t.rw.snappy = their.Version >= snappyProtocolVersion

	return their, nil
}

//读取握手消息的内容
func readProtocolHandshake(rw MsgReader, our *protoHandshake) (*protoHandshake, error) {
	msg, err := rw.ReadMsg()
	if err != nil {
		return nil, err
	}
	//判断数据的大小
	if msg.Size > baseProtocolMaxMsgSize {
		return nil, fmt.Errorf("message too big")
	}
	/* 接受对方消息时中断 */
	if msg.Code == discMsg {
		// Disconnect before protocol handshake is valid according to the
		// spec and we send it ourself if the posthanshake checks fail.
		// We can't return the reason directly, though, because it is echoed
		// back otherwise. Wrap it in a string instead.
		var reason [1]DiscReason
		rlp.Decode(msg.Payload, &reason)
		return nil, reason[0]
	}

	/* 如果对方返回的消息 并非协议握手标志位 */
	if msg.Code != handshakeMsg {
		return nil, fmt.Errorf("expected handshake, got %x", msg.Code)
	}
	/* remote返回的 其支持的协议数据 */
	var hs protoHandshake
	if err := msg.Decode(&hs); err != nil {
		return nil, err
	}
	if (hs.ID == discover.NodeID{}) {
		return nil, DiscInvalidIdentity
	}
	return &hs, nil
}

// 以太坊中receiver表示接收方,initiator 表示发起方
// 这两种模式下处理的流程是不同的。完成握手后。 生成了一个sec.可以理解为拿到了对称加密的密钥。 然后创建了一个newRLPXFrameRW帧读写器。完成加密信道的创建过程。
// doEncHandshake runs the protocol handshake using authenticated
// messages. the protocol handshake is the first authenticated message
// and also verifies whether the encryption handshake 'worked' and the
// remote side actually provided the right public key.
func (t *rlpx) doEncHandshake(prv *ecdsa.PrivateKey, dial *discover.Node) (discover.NodeID, error) {
	var (
		sec secrets //握手期间采用的加密对象
		err error
	)
	/* 如果拨号对象是空的, 以太坊中receiver表示接收方 */
	if dial == nil {
		sec, err = receiverEncHandshake(t.fd, prv, nil)
	} else {
		/* 拨号对象不为空,代表是主动发起方。以太坊中initiator 表示发起方，并返回共享秘钥  */
		sec, err = initiatorEncHandshake(t.fd, prv, dial.ID, nil)
	}

	if err != nil {
		return discover.NodeID{}, err
	}

	/* 开启全局锁 */
	t.wmu.Lock()
	/* 为当前连接，生成一个帧对象，目的是缓冲当前连接中的数据 */
	t.rw = newRLPXFrameRW(t.fd, sec)
	/* 关闭全局锁 */
	t.wmu.Unlock()

	/* 握手完成 */
	return sec.RemoteID, nil
}

// encHandshake contains the state of the encryption handshake.
type encHandshake struct {
	initiator bool
	remoteID  discover.NodeID

	remotePub            *ecies.PublicKey  // remote-pubk
	initNonce, respNonce []byte            // nonce
	randomPrivKey        *ecies.PrivateKey // ecdhe-random
	remoteRandomPub      *ecies.PublicKey  // ecdhe-random-pubk
}

/* 只有在握手期间才使用的一种加密方式 */
// secrets represents the connection secrets
// which are negotiated during the encryption handshake.
type secrets struct {
	RemoteID              discover.NodeID //远程地址
	AES, MAC              []byte          //AES加密标准，mac数据
	EgressMAC, IngressMAC hash.Hash       // 入站和出站mac
	Token                 []byte          //token
}

// RLPx v4 handshake auth (defined in EIP-8).
type authMsgV4 struct {
	gotPlain bool // whether read packet had plain format.

	Signature       [sigLen]byte //签名
	InitiatorPubkey [pubLen]byte //公钥
	Nonce           [shaLen]byte //序列号
	Version         uint         //版本
	//数据
	// Ignore additional fields (forward-compatibility)
	Rest []rlp.RawValue `rlp:"tail"`
}

// RLPx v4 handshake response (defined in EIP-8).
type authRespV4 struct {
	RandomPubkey [pubLen]byte
	Nonce        [shaLen]byte
	Version      uint

	// Ignore additional fields (forward-compatibility)
	Rest []rlp.RawValue `rlp:"tail"`
}

// 最后是secrets函数，这个函数是在handshake完成之后调用。
// 它通过自己的随机私钥和对端的公钥来生成一个共享秘密,这个共享秘密是瞬时的(只在当前这个链接中存在)。
// 所以当有一天私钥被破解。 之前的消息还是安全的
// secrets is called after the handshake is completed.
// It extracts the connection secrets from the handshake values.
/**
 * 生成双方的共享秘钥，数据传输时采用该秘钥加密数据。该共享秘钥只存在于当前的连接状态中，一旦连接断开，秘钥就删除掉。每次连接前的握手都需要生成这样一个秘钥信息。
 * @param auth 主动发起方的 握手授权信息
 * @param authResp 接收方回应的 响应授权信息
 * @return 返回一个共同的对称加密秘钥，以后数据传输时，采用该秘钥加密。
 */
func (h *encHandshake) secrets(auth, authResp []byte) (secrets, error) {

	/* 根据当前的私钥，对方的公钥，生成ECC霍夫曼树对称秘钥 */
	ecdheSecret, err := h.randomPrivKey.GenerateShared(h.remoteRandomPub, sskLen, sskLen)
	if err != nil {
		return secrets{}, err
	}

	// derive base secrets from ephemeral key agreement
	/* 对霍夫曼树秘钥进行签名 */
	sharedSecret := crypto.Keccak256(ecdheSecret, crypto.Keccak256(h.respNonce, h.initNonce))

	/* 在根据共享秘钥，ECC霍夫曼树秘钥生成 AES的签名 */
	aesSecret := crypto.Keccak256(ecdheSecret, sharedSecret)
	s := secrets{
		RemoteID: h.remoteID,
		AES:      aesSecret,
		MAC:      crypto.Keccak256(ecdheSecret, aesSecret),
	}

	// setup sha3 instances for the MACs
	mac1 := sha3.NewKeccak256()
	mac1.Write(xor(s.MAC, h.respNonce))
	mac1.Write(auth)
	mac2 := sha3.NewKeccak256()
	mac2.Write(xor(s.MAC, h.initNonce))
	mac2.Write(authResp)

	/* 如果是主动发起方 */
	if h.initiator {
		s.EgressMAC, s.IngressMAC = mac1, mac2
	} else {
		/* 如果是接收方 */
		s.EgressMAC, s.IngressMAC = mac2, mac1
	}

	return s, nil
}

/* 根据remote的公钥，本机的私钥生成一个共享秘钥 */
// staticSharedSecret returns the static shared secret, the result
// of key agreement between the local and remote static node key.
func (h *encHandshake) staticSharedSecret(prv *ecdsa.PrivateKey) ([]byte, error) {
	return ecies.ImportECDSA(prv).GenerateShared(h.remotePub, sskLen, sskLen)
}

// 首先看看链接的发起者的操作。首先通过makeAuthMsg创建了authMsg。
// 然后通过网络发送给对端。然后通过readHandshakeMsg读取对端的回应。
// 最后调用secrets创建了共享秘密
// initiatorEncHandshake negotiates a session token on conn.
// it should be called on the dialing side of the connection.
//
// prv is the local client's private key.
func initiatorEncHandshake(conn io.ReadWriter, prv *ecdsa.PrivateKey, remoteID discover.NodeID, token []byte) (s secrets, err error) {
	h := &encHandshake{initiator: true, remoteID: remoteID}

	/* 发起方根据本机的私钥构建authmessage（相当重要） */
	authMsg, err := h.makeAuthMsg(prv, token)
	if err != nil {
		return s, err
	}

	/* 根据授权信息 生成发送的数据包 */
	authPacket, err := sealEIP8(authMsg, h)
	if err != nil {
		return s, err
	}

	/* 这里可以看出，在握手阶段是只发送授权信息的验证，不发送真实数据的 */
	if _, err = conn.Write(authPacket); err != nil {
		return s, err
	}

	authRespMsg := new(authRespV4)
	/* 接受对方发送过来的响应数据包 */
	authRespPacket, err := readHandshakeMsg(authRespMsg, encAuthRespLen, prv, conn)
	if err != nil {
		return s, err
	}
	/* 校验接收到的数据的正确性 */
	if err := h.handleAuthResp(authRespMsg); err != nil {
		return s, err
	}
	/* 根据发送的数据授权包 + 接收到的响应包 生成一个共同的秘钥 */
	return h.secrets(authPacket, authRespPacket)
}

// 这个方法创建了initiator的handshake message。
// 首先对端的公钥可以通过对端的ID来获取。所以对端的公钥对于发起连接的人来说是知道的。
// 但是对于被连接的人来说，对端的公钥应该是不知道的
// makeAuthMsg creates the initiator handshake message.
func (h *encHandshake) makeAuthMsg(prv *ecdsa.PrivateKey, token []byte) (*authMsgV4, error) {

	/* 根据reomte的Id 计算出其公钥 */
	rpub, err := h.remoteID.Pubkey()
	if err != nil {
		return nil, fmt.Errorf("bad remoteID: %v", err)
	}

	/* 椭圆曲线数字签名算法（ECDSA）是使用椭圆曲线密码（ECC）对数字签名算法（DSA）的模拟 */
	/* ECIES是校验密钥是否和算法是否匹配，只有都符合条件了才能用于加密。所以ecc的公私秘钥就是ECIES的公私秘钥 */
	// 所以这个方法表示：根据ecc公钥，生成ecies公钥，并校验公钥是否符合ecc算法。这里之所以要校验，是因为我们的公钥是根据remoteId计算出来的。
	h.remotePub = ecies.ImportECDSAPublic(rpub)

	/* 这里随机生成一个 32字节的签名。当做请求的序列号。目的是抗重放攻击 */
	// Generate random initiator nonce.
	h.initNonce = make([]byte, shaLen)
	if _, err := rand.Read(h.initNonce); err != nil {
		return nil, err
	}

	/* 随机再生成一个椭圆的霍夫曼树的秘钥对 */
	// Generate random keypair to for ECDH.
	h.randomPrivKey, err = ecies.GenerateKey(rand.Reader, crypto.S256(), nil)
	if err != nil {
		return nil, err
	}

	// 这个地方应该是直接使用了静态的共享秘密。 使用自己的私钥和对方的公钥生成的一个共享秘密，也就是token。
	// 这个token作为共享的对称秘钥，不需要公开，也不需要传递。是专门在网络磋商中使用的(详见ECDH)。
	// Sign known message: static-shared-secret ^ nonce
	token, err = h.staticSharedSecret(prv)
	if err != nil {
		return nil, err
	}

	/* 生成MAC */
	signed := xor(token, h.initNonce)

	/* 用计算出的ECC霍夫曼对MAC进行签名 */
	signature, err := crypto.Sign(signed, h.randomPrivKey.ExportECDSA())
	if err != nil {
		return nil, err
	}

	/* 将签名，发起方的公钥，序列号封装到消息权限中 */
	msg := new(authMsgV4)
	copy(msg.Signature[:], signature)
	//这里把发起者的公钥告知对方。 这样对方使用自己的私钥和这个公钥可以生成静态的共享秘密
	copy(msg.InitiatorPubkey[:], crypto.FromECDSAPub(&prv.PublicKey)[1:])
	copy(msg.Nonce[:], h.initNonce)
	msg.Version = 4
	return msg, nil
}

/* 处理接收到的授权信息时：1、获取序列号，2、校验公钥是否正确 */
func (h *encHandshake) handleAuthResp(msg *authRespV4) (err error) {
	h.respNonce = msg.Nonce[:]
	h.remoteRandomPub, err = importPublicKey(msg.RandomPubkey[:])
	return err
}

/* 当接受到remote的rpc请求后，首先需要握手，这种连接方式是采用了一种token的方式来保证连接的*/
/* 这个方法必须在接收方接收到请求后进行调用 */
// receiverEncHandshake negotiates a session token on conn.
// it should be called on the listening side of the connection.
//
// prv is the local client's private key.
// token is the token from a previous session with this node.

/**
 * 当接受到remote的rpc请求后，首先需要握手，这种连接方式是采用了一种token的方式来保证连接的
 * 这个方法必须在接收方接收到请求后进行调用
 * @param conn  接收到的连接
 * @param prv 本机的私钥
 * @param token 保证双方连接的token。第一次对方连接进来时为空
 * @return secrets 双方的建立建立以来的秘钥(这个是新建的，每一个连接都有一个不一样的)
 **/
func receiverEncHandshake(conn io.ReadWriter, prv *ecdsa.PrivateKey, token []byte) (s secrets, err error) {

	/* 生成一个epi-8标准的 授权信息 */
	authMsg := new(authMsgV4)

	authPacket, err := readHandshakeMsg(authMsg, encAuthMsgLen, prv, conn)
	if err != nil {
		return s, err
	}
	h := new(encHandshake)
	if err := h.handleAuthMsg(authMsg, prv); err != nil {
		return s, err
	}

	authRespMsg, err := h.makeAuthResp()
	if err != nil {
		return s, err
	}
	var authRespPacket []byte
	if authMsg.gotPlain {
		authRespPacket, err = authRespMsg.sealPlain(h)
	} else {
		authRespPacket, err = sealEIP8(authRespMsg, h)
	}
	if err != nil {
		return s, err
	}
	if _, err = conn.Write(authRespPacket); err != nil {
		return s, err
	}
	return h.secrets(authPacket, authRespPacket)
}

func (h *encHandshake) handleAuthMsg(msg *authMsgV4, prv *ecdsa.PrivateKey) error {
	// Import the remote identity.
	h.initNonce = msg.Nonce[:]
	h.remoteID = msg.InitiatorPubkey
	rpub, err := h.remoteID.Pubkey()
	if err != nil {
		return fmt.Errorf("bad remoteID: %#v", err)
	}
	h.remotePub = ecies.ImportECDSAPublic(rpub)

	// Generate random keypair for ECDH.
	// If a private key is already set, use it instead of generating one (for testing).
	if h.randomPrivKey == nil {
		h.randomPrivKey, err = ecies.GenerateKey(rand.Reader, crypto.S256(), nil)
		if err != nil {
			return err
		}
	}

	// Check the signature.
	token, err := h.staticSharedSecret(prv)
	if err != nil {
		return err
	}
	signedMsg := xor(token, h.initNonce)
	remoteRandomPub, err := secp256k1.RecoverPubkey(signedMsg, msg.Signature[:])
	if err != nil {
		return err
	}
	h.remoteRandomPub, _ = importPublicKey(remoteRandomPub)
	return nil
}

func (h *encHandshake) makeAuthResp() (msg *authRespV4, err error) {
	// Generate random nonce.
	h.respNonce = make([]byte, shaLen)
	if _, err = rand.Read(h.respNonce); err != nil {
		return nil, err
	}

	msg = new(authRespV4)
	copy(msg.Nonce[:], h.respNonce)
	copy(msg.RandomPubkey[:], exportPubkey(&h.randomPrivKey.PublicKey))
	msg.Version = 4
	return msg, nil
}

func (msg *authMsgV4) sealPlain(h *encHandshake) ([]byte, error) {
	buf := make([]byte, authMsgLen)
	n := copy(buf, msg.Signature[:])
	n += copy(buf[n:], crypto.Keccak256(exportPubkey(&h.randomPrivKey.PublicKey)))
	n += copy(buf[n:], msg.InitiatorPubkey[:])
	n += copy(buf[n:], msg.Nonce[:])
	buf[n] = 0 // token-flag
	return ecies.Encrypt(rand.Reader, h.remotePub, buf, nil, nil)
}

func (msg *authMsgV4) decodePlain(input []byte) {
	n := copy(msg.Signature[:], input)
	n += shaLen // skip sha3(initiator-ephemeral-pubk)
	n += copy(msg.InitiatorPubkey[:], input[n:])
	copy(msg.Nonce[:], input[n:])
	msg.Version = 4
	msg.gotPlain = true
}

func (msg *authRespV4) sealPlain(hs *encHandshake) ([]byte, error) {
	buf := make([]byte, authRespLen)
	n := copy(buf, msg.RandomPubkey[:])
	copy(buf[n:], msg.Nonce[:])
	return ecies.Encrypt(rand.Reader, hs.remotePub, buf, nil, nil)
}

func (msg *authRespV4) decodePlain(input []byte) {
	n := copy(msg.RandomPubkey[:], input)
	copy(msg.Nonce[:], input[n:])
	msg.Version = 4
}

/* 加密握手是的数据大小， */
var padSpace = make([]byte, 300)

// sealEIP8方法，这个方法是一个组包方法，对msg进行rlp的编码。 填充一些数据。
// 然后使用对方的公钥把数据进行加密。 这意味着只有对方的私钥才能解密这段信息
func sealEIP8(msg interface{}, h *encHandshake) ([]byte, error) {

	/* 用于保存授权信息 */
	buf := new(bytes.Buffer)

	/* 授权信息 的RLP 编码 */
	if err := rlp.Encode(buf, msg); err != nil {
		return nil, err
	}
	// pad with random amount of data. the amount needs to be at least 100 bytes to make
	// the message distinguishable from pre-EIP-8 handshakes.
	/* padSpace的长度是300，这里随机产生一个大于100的数n，然后获取padSpace 中0-n的数据动态字节数组 */
	/* 这里之所以是必须要求大于100，主要的原因是要保证 与之前的握手 的数据是可以分辨的。如果小于100，则可能无法分辨上次与这次的数据？？这是什么原因 */
	/* 这个叫做拼接空间，这么做是为什么??? */
	pad := padSpace[:mrand.Intn(len(padSpace)-100)+100]

	/* 然后将要传送的数据 写到动态字节数组中 */
	buf.Write(pad)

	/* 保存头的头+授权信息的长度 */
	prefix := make([]byte, 2)

	/* 将数据长度 + ecies的头长度 放入到prefix中 */
	binary.BigEndian.PutUint16(prefix, uint16(buf.Len()+eciesOverhead))

	/* 采用remote的公钥 对授权信息加密。这里可以看出，握手阶段是不发送数据的 */
	enc, err := ecies.Encrypt(rand.Reader, h.remotePub, buf.Bytes(), nil, prefix)
	return append(prefix, enc...), err
}

type plainDecoder interface {
	decodePlain([]byte)
}

/**
 * 从remote的连接中 读取出 rpc握手的授权信息
 *
 * readHandshakeMsg这个方法会从两个地方调用。
 * 一个是在initiatorEncHandshake。
 * 一个就是在receiverEncHandshake。
 * 这个方法比较简单。 首先用一种格式尝试解码。如果不行就换另外一种。应该是一种兼容性的设置。
 * 基本上就是使用自己的私钥进行解码然后调用rlp解码成结构体。
 * 结构体的描述就是下面的authRespV4,里面最重要的就是对端的随机公钥。
 * 双方通过自己的私钥和对端的随机公钥可以得到一样的共享秘密。 而这个共享秘密是第三方拿不到的
 * @param msg  要生成的授权信息接受对象
 * @param plainSize 响应包的数据理论长度
 * @param prv 本机的私钥
 * @return r remote的连接
 **/
func readHandshakeMsg(msg plainDecoder, plainSize int, prv *ecdsa.PrivateKey, r io.Reader) ([]byte, error) {

	/* 保存authRespV4的字节码  */
	buf := make([]byte, plainSize)

	/* 从流中读取出authRespV4 */
	if _, err := io.ReadFull(r, buf); err != nil {
		return buf, err
	}

	/* 握手阶段采用ECIES 秘钥 */
	// Attempt decoding pre-EIP-8 "plain" format.
	key := ecies.ImportECDSA(prv)

	/* 用上述产生的私钥，解密authRespV4 */
	if dec, err := key.Decrypt(buf, nil, nil); err == nil {
		msg.decodePlain(dec)
		return buf, nil
	}

	/* 读取出数据的总长度 */
	// Could be EIP-8 format, try that.
	prefix := buf[:2]

	/* 按照16进制转为无符号int */
	size := binary.BigEndian.Uint16(prefix)
	/* 如果这个长度 小于理论的长度。校验失败 */
	if size < uint16(plainSize) {
		return buf, fmt.Errorf("size underflow, need at least %d bytes", plainSize)
	}

	/* 把数据全部读取到buf中 */
	buf = append(buf, make([]byte, size-uint16(plainSize)+2)...)
	if _, err := io.ReadFull(r, buf[plainSize:]); err != nil {
		return buf, err
	}

	/* 对数据进行非对称的解密 */
	dec, err := key.Decrypt(buf[2:], nil, prefix)
	if err != nil {
		return buf, err
	}
	// Can't use rlp.DecodeBytes here because it rejects
	// trailing data (forward-compatibility).
	s := rlp.NewStream(bytes.NewReader(dec), 0)

	/* 返回解密后的字节数组 */
	return buf, s.Decode(msg)
}

// importPublicKey unmarshals 512 bit public keys.
func importPublicKey(pubKey []byte) (*ecies.PublicKey, error) {
	var pubKey65 []byte
	switch len(pubKey) {
	case 64:
		// add 'uncompressed key' flag
		pubKey65 = append([]byte{0x04}, pubKey...)
	case 65:
		pubKey65 = pubKey
	default:
		return nil, fmt.Errorf("invalid public key length %v (expect 64/65)", len(pubKey))
	}
	// TODO: fewer pointless conversions
	pub := crypto.ToECDSAPub(pubKey65)
	if pub.X == nil {
		return nil, fmt.Errorf("invalid public key")
	}
	return ecies.ImportECDSAPublic(pub), nil
}

func exportPubkey(pub *ecies.PublicKey) []byte {
	if pub == nil {
		panic("nil pubkey")
	}
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)[1:]
}

func xor(one, other []byte) (xor []byte) {
	xor = make([]byte, len(one))
	for i := 0; i < len(one); i++ {
		xor[i] = one[i] ^ other[i]
	}
	return xor
}

var (
	// this is used in place of actual frame header data.
	// TODO: replace this when Msg contains the protocol type code.
	zeroHeader = []byte{0xC2, 0x80, 0x80}
	// sixteen zero bytes
	zero16 = make([]byte, 16)
)

// rlpx数据分帧 读取写入操作器
// rlpxFrameRW implements a simplified version of RLPx framing.
// chunked messages are not supported and all headers are equal to
// zeroHeader.
//
// rlpxFrameRW is not safe for concurrent use from multiple goroutines.
type rlpxFrameRW struct {
	conn io.ReadWriter //连接的流
	enc  cipher.Stream //加密流
	dec  cipher.Stream //解密流

	macCipher  cipher.Block //数据块大小
	egressMAC  hash.Hash    //输出流mac地址的hash值
	ingressMAC hash.Hash    //输入流mac地址 的hash值

	snappy bool
}

func newRLPXFrameRW(conn io.ReadWriter, s secrets) *rlpxFrameRW {

	/* 判断mac是否加密 */
	macc, err := aes.NewCipher(s.MAC)
	if err != nil {
		panic("invalid MAC secret: " + err.Error())
	}
	/* 加密方式是否为aes */
	encc, err := aes.NewCipher(s.AES)
	if err != nil {
		panic("invalid AES secret: " + err.Error())
	}
	// we use an all-zeroes IV for AES because the key used
	// for encryption is ephemeral.
	iv := make([]byte, encc.BlockSize())

	/* 根据加密方式 生成帧对象 */
	return &rlpxFrameRW{
		conn:       conn,
		enc:        cipher.NewCTR(encc, iv),
		dec:        cipher.NewCTR(encc, iv),
		macCipher:  macc,
		egressMAC:  s.EgressMAC,
		ingressMAC: s.IngressMAC,
	}
}

func (rw *rlpxFrameRW) WriteMsg(msg Msg) error {
	ptype, _ := rlp.EncodeToBytes(msg.Code)

	// if snappy is enabled, compress message now
	if rw.snappy {
		if msg.Size > maxUint24 {
			return errPlainMessageTooLarge
		}
		payload, _ := ioutil.ReadAll(msg.Payload)
		payload = snappy.Encode(nil, payload)

		msg.Payload = bytes.NewReader(payload)
		msg.Size = uint32(len(payload))
	}
	// write header
	headbuf := make([]byte, 32)
	fsize := uint32(len(ptype)) + msg.Size
	if fsize > maxUint24 {
		return errors.New("message size overflows uint24")
	}
	putInt24(fsize, headbuf) // TODO: check overflow
	copy(headbuf[3:], zeroHeader)
	rw.enc.XORKeyStream(headbuf[:16], headbuf[:16]) // first half is now encrypted

	// write header MAC
	copy(headbuf[16:], updateMAC(rw.egressMAC, rw.macCipher, headbuf[:16]))
	if _, err := rw.conn.Write(headbuf); err != nil {
		return err
	}

	// write encrypted frame, updating the egress MAC hash with
	// the data written to conn.
	tee := cipher.StreamWriter{S: rw.enc, W: io.MultiWriter(rw.conn, rw.egressMAC)}
	if _, err := tee.Write(ptype); err != nil {
		return err
	}
	if _, err := io.Copy(tee, msg.Payload); err != nil {
		return err
	}
	if padding := fsize % 16; padding > 0 {
		if _, err := tee.Write(zero16[:16-padding]); err != nil {
			return err
		}
	}

	// write frame MAC. egress MAC hash is up to date because
	// frame content was written to it as well.
	fmacseed := rw.egressMAC.Sum(nil)
	mac := updateMAC(rw.egressMAC, rw.macCipher, fmacseed)
	_, err := rw.conn.Write(mac)
	return err
}

func (rw *rlpxFrameRW) ReadMsg() (msg Msg, err error) {
	// read the header
	headbuf := make([]byte, 32)
	if _, err := io.ReadFull(rw.conn, headbuf); err != nil {
		return msg, err
	}
	// verify header mac
	shouldMAC := updateMAC(rw.ingressMAC, rw.macCipher, headbuf[:16])
	if !hmac.Equal(shouldMAC, headbuf[16:]) {
		return msg, errors.New("bad header MAC")
	}
	rw.dec.XORKeyStream(headbuf[:16], headbuf[:16]) // first half is now decrypted
	fsize := readInt24(headbuf)
	// ignore protocol type for now

	// read the frame content
	var rsize = fsize // frame size rounded up to 16 byte boundary
	if padding := fsize % 16; padding > 0 {
		rsize += 16 - padding
	}
	framebuf := make([]byte, rsize)
	if _, err := io.ReadFull(rw.conn, framebuf); err != nil {
		return msg, err
	}

	// read and validate frame MAC. we can re-use headbuf for that.
	rw.ingressMAC.Write(framebuf)
	fmacseed := rw.ingressMAC.Sum(nil)
	if _, err := io.ReadFull(rw.conn, headbuf[:16]); err != nil {
		return msg, err
	}
	shouldMAC = updateMAC(rw.ingressMAC, rw.macCipher, fmacseed)
	if !hmac.Equal(shouldMAC, headbuf[:16]) {
		return msg, errors.New("bad frame MAC")
	}

	// decrypt frame content
	rw.dec.XORKeyStream(framebuf, framebuf)

	// decode message code
	content := bytes.NewReader(framebuf[:fsize])
	if err := rlp.Decode(content, &msg.Code); err != nil {
		return msg, err
	}
	msg.Size = uint32(content.Len())
	msg.Payload = content

	// if snappy is enabled, verify and decompress message
	if rw.snappy {
		payload, err := ioutil.ReadAll(msg.Payload)
		if err != nil {
			return msg, err
		}
		size, err := snappy.DecodedLen(payload)
		if err != nil {
			return msg, err
		}
		if size > int(maxUint24) {
			return msg, errPlainMessageTooLarge
		}
		payload, err = snappy.Decode(nil, payload)
		if err != nil {
			return msg, err
		}
		msg.Size, msg.Payload = uint32(size), bytes.NewReader(payload)
	}
	return msg, nil
}

// updateMAC reseeds the given hash with encrypted seed.
// it returns the first 16 bytes of the hash sum after seeding.
func updateMAC(mac hash.Hash, block cipher.Block, seed []byte) []byte {
	aesbuf := make([]byte, aes.BlockSize)
	block.Encrypt(aesbuf, mac.Sum(nil))
	for i := range aesbuf {
		aesbuf[i] ^= seed[i]
	}
	mac.Write(aesbuf)
	return mac.Sum(nil)[:16]
}

func readInt24(b []byte) uint32 {
	return uint32(b[2]) | uint32(b[1])<<8 | uint32(b[0])<<16
}

func putInt24(v uint32, b []byte) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}
