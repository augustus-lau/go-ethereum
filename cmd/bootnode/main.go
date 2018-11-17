// Copyright 2015 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// bootnode runs a bootstrap node for the Ethereum Discovery Protocol.
package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/discv5"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

/*以太坊在启动时需要告之至少一个对等节点，这样才能接入整个以太坊网络，
/* bootnode相当于一个第三方的中介，node在启动时会将自己的信息注册到bootnode的路由中，
/* 并且会从bootnode得到其它节点的路由信息，一旦有了对等节点信息后就可以不需要连接bootnode。
/* 公有链的节点硬编码了一些bootnode节点地址*/

//生成私钥文件，可以在命令行运行 go run main.go -genkey 来生成私钥
func main() {

	// P- START,   启动开始  p2p启动的八大问题。。。。。 加密，网络环境，公钥私钥生成，黑名单，udp，基于udp的p2p
	// P-ONE: 读取启动参数
	var (
		listenAddr  = flag.String("addr", ":30301", "listen address")
		genKey      = flag.String("genkey", "", "generate a node key")
		writeAddr   = flag.Bool("writeaddress", false, "write out the node's pubkey hash and quit")
		nodeKeyFile = flag.String("nodekey", "", "private key filename")
		nodeKeyHex  = flag.String("nodekeyhex", "", "private key as hex (for testing)")
		natdesc     = flag.String("nat", "none", "port mapping mechanism (any|none|upnp|pmp|extip:<IP>)")
		netrestrict = flag.String("netrestrict", "", "restrict network communication to the given IP networks (CIDR masks)")
		runv5       = flag.Bool("v5", false, "run a v5 topic discovery bootnode")
		verbosity   = flag.Int("verbosity", int(log.LvlInfo), "log verbosity (0-9)")
		vmodule     = flag.String("vmodule", "", "log verbosity pattern")

		//椭圆曲线非对称加密的 秘钥
		nodeKey *ecdsa.PrivateKey
		err     error
	)
	flag.Parse()

	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	glogger.Verbosity(log.Lvl(*verbosity))
	glogger.Vmodule(*vmodule)
	log.Root().SetHandler(glogger)

	// P-TWO: 解析对应的网络环境，nat
	natm, err := nat.Parse(*natdesc)
	if err != nil {
		utils.Fatalf("-nat: %v", err)
	}

	switch {

	// P-THREE:重点查看如何生成秘钥
	case *genKey != "":

		// 私钥
		nodeKey, err = crypto.GenerateKey()
		if err != nil {
			utils.Fatalf("could not generate key: %v", err)
		}
		if err = crypto.SaveECDSA(*genKey, nodeKey); err != nil {
			utils.Fatalf("%v", err)
		}
		return
	case *nodeKeyFile == "" && *nodeKeyHex == "":
		utils.Fatalf("Use -nodekey or -nodekeyhex to specify a private key")
	case *nodeKeyFile != "" && *nodeKeyHex != "":
		utils.Fatalf("Options -nodekey and -nodekeyhex are mutually exclusive")
	case *nodeKeyFile != "":
		if nodeKey, err = crypto.LoadECDSA(*nodeKeyFile); err != nil {
			utils.Fatalf("-nodekey: %v", err)
		}
	case *nodeKeyHex != "":
		if nodeKey, err = crypto.HexToECDSA(*nodeKeyHex); err != nil {
			utils.Fatalf("-nodekeyhex: %v", err)
		}
	}

	// P-FOUR:  将公钥保存到当前节点的对象中
	if *writeAddr {
		fmt.Printf("%v\n", discover.PubkeyID(&nodeKey.PublicKey))
		os.Exit(0)
	}
	// P-FIVE: 黑名单数据列表
	var restrictList *netutil.Netlist
	if *netrestrict != "" {
		restrictList, err = netutil.ParseNetlist(*netrestrict)
		if err != nil {
			utils.Fatalf("-netrestrict: %v", err)
		}
	}

	// P-SIX: udp服务
	addr, err := net.ResolveUDPAddr("udp", *listenAddr)
	if err != nil {
		utils.Fatalf("-ResolveUDPAddr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		utils.Fatalf("-ListenUDP: %v", err)
	}

	// P-SEVEN: 获取真实的地址
	realaddr := conn.LocalAddr().(*net.UDPAddr)
	if natm != nil {
		if !realaddr.IP.IsLoopback() {
			go nat.Map(natm, nil, "udp", realaddr.Port, realaddr.Port, "ethereum discovery")
		}
		// TODO: react to external IP changes over time.
		if ext, err := natm.ExternalIP(); err == nil {
			realaddr = &net.UDPAddr{IP: ext, Port: realaddr.Port}
		}
	}

	// P-EIGHT:采用哪个版本的p2p
	if *runv5 {
		if _, err := discv5.ListenUDP(nodeKey, conn, realaddr, "", restrictList); err != nil {
			utils.Fatalf("%v", err)
		}
	} else {
		cfg := discover.Config{
			PrivateKey:   nodeKey,
			AnnounceAddr: realaddr,
			NetRestrict:  restrictList,
		}
		if _, err := discover.ListenUDP(conn, cfg); err != nil {
			utils.Fatalf("%v", err)
		}
	}

	// P-NIGHT:无线循环---服务启动
	select {}
}
