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

// Package discv5 implements the RLPx v5 Topic Discovery Protocol.
//
// The Topic Discovery protocol provides a way to find RLPx nodes that
// can be connected to. It uses a Kademlia-like protocol to maintain a
// distributed database of the IDs and endpoints of all listening
// nodes.
package discv5

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sort"

	"github.com/ethereum/go-ethereum/common"
)

const (
	//当路由到某个子树时，会从该子树随机抽取alpha个节点发送请求。
	alpha = 3 // Kademlia concurrency factor

	//每层保存节点数
	bucketSize = 16 // Kademlia bucket size

	//256长度的节点
	hashBits = len(common.Hash{}) * 8

	//多少层
	nBuckets = hashBits + 1 // Number of buckets

	//查找节点最多失败的次数
	maxFindnodeFailures = 5
)

//内存路由表
type Table struct {
	count         int               // number of nodes 节点的总个数
	buckets       [nBuckets]*bucket // index of known nodes by distance 到本节点的距离索引
	nodeAddedHook func(*Node)       // for testing
	self          *Node             // metadata of the local node //当前节点
}

// bucket contains nodes, ordered by their last activity. the entry
// that was most recently active is the first element in entries.
type bucket struct {
	entries      []*Node
	replacements []*Node
}

func newTable(ourID NodeID, ourAddr *net.UDPAddr) *Table {
	self := NewNode(ourID, ourAddr.IP, uint16(ourAddr.Port), uint16(ourAddr.Port))
	tab := &Table{self: self}
	for i := range tab.buckets {
		tab.buckets[i] = new(bucket)
	}
	return tab
}

//是否答应路由表
const printTable = false

// chooseBucketRefreshTarget selects random refresh targets to keep all Kademlia
// buckets filled with live connections and keep the network topology healthy.
// This requires selecting addresses closer to our own with a higher probability
// in order to refresh closer buckets too.
//
// This algorithm approximates the distance distribution of existing nodes in the
// table by selecting a random node from the table and selecting a target address
// with a distance less than twice of that of the selected node.
// This algorithm will be improved later to specifically target the least recently
// used buckets.
// common.Hash是32 * 8位
// 这个方法的作用是随机产生节点的hash,以填充kad桶。但是产生的节点id必须是最接近当前节点的值
// 产生一个高8位于目标节点相同，的随机节点hash
// 用来做什么的
func (tab *Table) chooseBucketRefreshTarget() common.Hash {

	// bucket的总个数
	entries := 0
	if printTable {
		fmt.Println()
	}

	//统计当前节点的个数
	for i, b := range tab.buckets {
		entries += len(b.entries)
		if printTable {
			for _, e := range b.entries {
				fmt.Println(i, e.state, e.addr().String(), e.ID.String(), e.sha.Hex())
			}
		}
	}

	//获取当前节点的高8位
	prefix := binary.BigEndian.Uint64(tab.self.sha[0:8])

	//64位1
	dist := ^uint64(0)
	//由于当前一共有entries个数据，这里随机返回一个 [0 ,总节点数]之间的数据，根据这个随机数来选择哪个节点
	entry := int(randUint(uint32(entries + 1)))

	//随机在tab表中找一个节点
	for _, b := range tab.buckets {

		//当随机数小于当前层的总节点数时，在当前层找到一个节点
		if entry < len(b.entries) {
			// 随机找到一个节点
			n := b.entries[entry]
			//高位一个字节的xor距离计算-- 大端的无符号64位--- 计算高8位的距离
			dist = binary.BigEndian.Uint64(n.sha[0:8]) ^ prefix
			break
		}
		//如果大于则 entry = entry - len(b.entries)
		entry -= len(b.entries)
	}

	ddist := ^uint64(0)
	//因为先采用高8位运算，只要高8位不同，则必然成立，如果高8位全相同，则都为0
	//所以，只要xor > 0 就说明存在距离
	if dist+dist > dist {
		ddist = dist
	}
	//ddist就是到目标节点的xor距离，randUint64n(ddist)随机产生一个小于该距离的值
	// 还原该节点的的前缀，双异或 等于自己
	targetPrefix := prefix ^ randUint64n(ddist)

	//	ddist := ^uint64(0)

	var target common.Hash

	//将随机产生的高8位放入到目标节点中
	binary.BigEndian.PutUint64(target[0:8], targetPrefix)

	//将高8位后面的低位 随机产生
	rand.Read(target[8:])
	return target
}

// readRandomNodes fills the given slice with random nodes from the
// table. It will not write the same node more than once. The nodes in
// the slice are copies and can be modified by the caller.
// 这个方法buf是提供一个要返回的数据空数组，然后从table路由表中随机取出n个数据 将buf填满----这是为了解决什么问题
// 方案：经过层之间的变换来随机取出buf个大小的节点
// 这里我理解上 随机洗牌并筛选n个节点 没必要按照这种方式来，可以按照自己的方式来洗牌
func (tab *Table) readRandomNodes(buf []*Node) (n int) {
	// TODO: tree-based buckets would help here
	// Find all non-empty buckets and get a fresh slice of their entries.
	var buckets [][]*Node

	//将tab中的数据放入到临时变量buckets中--找到非空的buckets
	for _, b := range tab.buckets {
		if len(b.entries) > 0 {
			buckets = append(buckets, b.entries[:])
		}
	}
	//如果是空的 返回0
	if len(buckets) == 0 {
		return 0
	}
	// Shuffle the buckets.重新洗牌临时变量buckets中的值
	// 遍历层数
	for i := uint32(len(buckets)) - 1; i > 0; i-- {

		//随机找到比小的一层
		j := randUint(i)

		//将第i层数据与第j层数据整行互换(随机的，目的就是要打乱原来的排序)
		buckets[i], buckets[j] = buckets[j], buckets[i]
	}

	// Move head of each bucket into buf, removing buckets that become empty.
	var i, j int
	//随机取buf个数据 ，放入到buf中，且要从table中删除掉
	for ; i < len(buf); i, j = i+1, (j+1)%len(buckets) {
		b := buckets[j]
		//将第j层中的第一个节点取出 放入到buf数组的末尾
		buf[i] = &(*b[0])
		//将第j层第二个数据后的所有内容向前移动一位
		buckets[j] = b[1:]

		//如果第j层上只有一个数据，那么取出后该层就没有数据了
		if len(b) == 1 {
			//将j层之后的数据 整体向前移动一层，以为这去掉j层
			buckets = append(buckets[:j], buckets[j+1:]...)
		}
		if len(buckets) == 0 {
			break
		}
	}
	return i + 1
}

/**
 * @param max 表示最大的个数
 * @return uints32 返回一个最大值内的随机值
 *
 */
func randUint(max uint32) uint32 {
	if max < 2 {
		return 0
	}
	var b [4]byte
	//随机产生一个32位的无符号整形值
	rand.Read(b[:])
	//根据最大值取余数，来随机找一个数组中的值
	return binary.BigEndian.Uint32(b[:]) % max
}

//随机产生一个不大于max的值
func randUint64n(max uint64) uint64 {
	if max < 2 {
		return 0
	}
	var b [8]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:]) % max
}

// 查找nresults个  离target最近的节点
// closest returns the n nodes in the table that are closest to the
// given id. The caller must hold tab.mutex.
func (tab *Table) closest(target common.Hash, nresults int) *nodesByDistance {
	// This is a very wasteful way to find the closest nodes but
	// obviously correct. I believe that tree-based buckets would make
	// this easier to implement efficiently.
	// 最近的节点 对象
	close := &nodesByDistance{target: target}

	//查找方法，遍历每一个节点，然后与target进行距离的对比，然后将节点保存
	for _, b := range tab.buckets {
		for _, n := range b.entries {
			close.push(n, nresults)
		}
	}
	return close
}

// 添加一个节点到路由表中
// add attempts to add the given node its corresponding bucket. If the
// bucket has space available, adding the node succeeds immediately.
// Otherwise, the node is added to the replacement cache for the bucket.
func (tab *Table) add(n *Node) (contested *Node) {
	//fmt.Println("add", n.addr().String(), n.ID.String(), n.sha.Hex())
	if n.ID == tab.self.ID {
		return
	}
	//找到第n层
	b := tab.buckets[logdist(tab.self.sha, n.sha)]
	switch {
	case b.bump(n):
		// n exists in b.
		return nil
	case len(b.entries) < bucketSize:
		// b has space available.
		b.addFront(n)
		tab.count++
		if tab.nodeAddedHook != nil {
			tab.nodeAddedHook(n)
		}
		return nil
	default: //如果b中已经满了，暂时先放到replacement数组中
		// b has no space left, add to replacement cache
		// and revalidate the last entry.
		// TODO: drop previous node
		b.replacements = append(b.replacements, n)
		if len(b.replacements) > bucketSize {
			//剔除掉最先进来的数据,整体向前移动一位
			copy(b.replacements, b.replacements[1:])
			//将末尾节点置空
			b.replacements = b.replacements[:len(b.replacements)-1]
		}
		//返回最后一个节点
		return b.entries[len(b.entries)-1]
	}
}

//添加一个数组到路由表中
// stuff adds nodes the table to the end of their corresponding bucket
// if the bucket is not full.
func (tab *Table) stuff(nodes []*Node) {
outer:
	for _, n := range nodes {
		if n.ID == tab.self.ID {
			continue // don't add self
		}
		bucket := tab.buckets[logdist(tab.self.sha, n.sha)]
		for i := range bucket.entries {
			if bucket.entries[i].ID == n.ID {
				continue outer // already in bucket
			}
		}
		if len(bucket.entries) < bucketSize {
			bucket.entries = append(bucket.entries, n)
			tab.count++
			if tab.nodeAddedHook != nil {
				tab.nodeAddedHook(n)
			}
		}
	}
}

// delete removes an entry from the node table (used to evacuate
// failed/non-bonded discovery peers).
func (tab *Table) delete(node *Node) {
	//fmt.Println("delete", node.addr().String(), node.ID.String(), node.sha.Hex())
	bucket := tab.buckets[logdist(tab.self.sha, node.sha)]
	for i := range bucket.entries {
		if bucket.entries[i].ID == node.ID {
			bucket.entries = append(bucket.entries[:i], bucket.entries[i+1:]...)
			tab.count--
			return
		}
	}
}

func (tab *Table) deleteReplace(node *Node) {
	b := tab.buckets[logdist(tab.self.sha, node.sha)]
	i := 0
	for i < len(b.entries) {
		if b.entries[i].ID == node.ID {
			b.entries = append(b.entries[:i], b.entries[i+1:]...)
			tab.count--
		} else {
			i++
		}
	}
	// refill from replacement cache
	// TODO: maybe use random index
	if len(b.entries) < bucketSize && len(b.replacements) > 0 {
		ri := len(b.replacements) - 1
		b.addFront(b.replacements[ri])
		tab.count++
		b.replacements[ri] = nil
		b.replacements = b.replacements[:ri]
	}
}

//添加到数组最前面
func (b *bucket) addFront(n *Node) {
	b.entries = append(b.entries, nil)
	copy(b.entries[1:], b.entries)
	b.entries[0] = n
}

//如果n在列表中，将n移动到最前，否则不做任何处理
func (b *bucket) bump(n *Node) bool {
	for i := range b.entries {
		if b.entries[i].ID == n.ID {
			// move it to the front
			copy(b.entries[1:], b.entries[:i])
			b.entries[0] = n
			return true
		}
	}
	return false
}

// nodesByDistance is a list of nodes, ordered by
// distance to target.
type nodesByDistance struct {
	entries []*Node
	target  common.Hash
}

/**
 * @param n  节点
 * @param maxElems 某个距离k 内的最大节点可数
 *
 * @func 将n加入到找到的节点列表中
 */
// push adds the given node to the list, keeping the total size below maxElems.
func (h *nodesByDistance) push(n *Node, maxElems int) {
	//首先对保存节点的数据nodesByDistance.entries 按照记录进行排序
	ix := sort.Search(len(h.entries), func(i int) bool {
		return distcmp(h.target, h.entries[i].sha, n.sha) > 0
	})

	//如果当前的已经找到的个数小于16个，则直接添加
	if len(h.entries) < maxElems {
		h.entries = append(h.entries, n)
	}
	//如果等于就什么也不做-- 这里应该不对吧？？？？？
	if ix == len(h.entries) {
		// farther away than all nodes we already have.
		// if there was room for it, the node is now the last element.
	} else { //如果大于
		// slide existing entries down to make room
		// this will overwrite the entry we just appended.
		copy(h.entries[ix+1:], h.entries[ix:])
		h.entries[ix] = n
	}
}
