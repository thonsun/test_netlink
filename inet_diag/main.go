package main

import (
	"fmt"
	"github.com/mdlayher/netlink"
	"log"
	"syscall"
)

const (
	inetDiag = 4 // netlink_inet_addr 协议号
	SOCK_DIAG_BY_FAMILY netlink.HeaderType = 20 //
)

var (
	src = [4]uint32{167955888,0,0,0}
	sport uint16 = 22
	dst = [4]uint32{167953822,0,0,0}
	dport uint16 = 60486
)

func main() {
	c, err := netlink.Dial(inetDiag,nil)
	if err != nil{
		log.Fatalf("failed to dial netlink:%v",err)
	}
	defer c.Close()

	//setup
	conn_req := inet_diag_req_v2{
		sdiag_family:syscall.AF_INET,
		sdiag_protocol:syscall.IPPROTO_TCP,
		// 特定的ip port socket inode 查询
		idiag_stats:((1<<TCP_LISTEN) | (1<<TCP_ESTABLISHED)),
		sdiag_ext: (1<<(INET_DIAG_INFO-1)),
		//id: inet_diag_sockid{idiag_src:src,idiag_sport:sport,idiag_dst:dst,idiag_dport:dport},
	}
	data, err := conn_req.marshalBinary()
	if err != nil{
		log.Fatalln("data to byte error:",err)
	}
	req := netlink.Message{
		Header: netlink.Header{
			Type: SOCK_DIAG_BY_FAMILY,
			Flags:netlink.Request|netlink.Dump,
		},
		Data: data,
	}

	m, err := c.Send(req)
	if err != nil {
		log.Printf("send req msg error:%v",err)
	}
	fmt.Printf("send status:%v\n",m)

	msgs, err := c.Receive()
	if err != nil {
		fmt.Printf("recieve msg error:%#v\n",err)
	}
	//fmt.Printf("recieve msg:%v\n",msg)
	for _,msg := range msgs {
		resp := unmarshresp(msg.Data)
		fmt.Printf("src:%v:%v dst:%v:%v user:%v inode:%v\n",unint32LE2BE(resp.id.idiag_src[0]),
			unint16LE2BE(resp.id.idiag_sport),unint32LE2BE(resp.id.idiag_dst[0]),unint16LE2BE(resp.id.idiag_dport),
			resp.idiag_uid,resp.idiag_inode)
	}
}
