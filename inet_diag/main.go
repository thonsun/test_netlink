package main

import (
	"encoding/binary"
	"fmt"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"log"
	"syscall"
)

const (
	inetDiag = 4 // netlink_inet_addr 协议号
	SOCK_DIAG_BY_FAMILY netlink.HeaderType = 20 //nlmsg_hdr nlmsg_type 类型
)

// home
// 指定IP 五元组信息
var (
	src = [4]uint32{3232237682,0,0,0} // 兼容ipv6,ipv4 只用到第一个数组
	sport uint16 = 22
	dst = [4]uint32{3232237811,0,0,0}
	dport uint16 = 63044
)

func main() {
	c, err := netlink.Dial(inetDiag,nil)
	if err != nil{
		log.Fatalf("failed to create netlink socket:%v",err)
	}
	defer c.Close()

	//setup req msg
	conn_req := inet_diag_req_v2{
		sdiag_family:syscall.AF_INET,
		sdiag_protocol:syscall.IPPROTO_TCP,
		idiag_stats:((1<<TCP_LISTEN) | (1<<TCP_ESTABLISHED)),
		// sdiag_ext: (1<<(INET_DIAG_INFO-1)),需要查询那些消息
		// 特定的ip port socket inode 查询
		// 注意 C 结构体中说明 id 中ip | port 固定为大端序的
		id: inet_diag_sockid{idiag_src:src,idiag_sport:sport,idiag_dst:dst,idiag_dport:dport},
	}
	// 将struct 消息转为 []byte 数组
	data, err := conn_req.marshalBinary()
	if err != nil{
		log.Fatalln("data to byte error:",err)
	}
	req := netlink.Message{
		Header: netlink.Header{
			Type: SOCK_DIAG_BY_FAMILY,
			Flags:netlink.Request | netlink.Dump,
		},
		Data: data,
	}

	m, err := c.Send(req)
	if err != nil {
		log.Printf("send req msg error:%v",err)
	}
	fmt.Printf("send msg status:%v\n",m)

	msgs, err := c.Receive()
	if err != nil {
		fmt.Printf("recieve msg error:%#v\n",err)
	}

	for _,msg := range msgs {
		// 将[]byte 消息转为struce  结构体
		resp := unmarshresp(msg.Data)
		fmt.Printf("src:%v:%v dst:%v:%v user:%v inode:%v\n",unint32LE2BE(resp.id.idiag_src[0]),
			unint16LE2BE(resp.id.idiag_sport),unint32LE2BE(resp.id.idiag_dst[0]),unint16LE2BE(resp.id.idiag_dport),
			resp.idiag_uid,resp.idiag_inode)
	}
}

// 下面是将C struct 转为 go struct
// socket identity
type inet_diag_sockid struct {
	idiag_sport uint16
	idiag_dport uint16
	idiag_src [4]uint32
	idiag_dst [4]uint32 // ipv4 32 | ipv6 128 的兼容
	idiag_if uint32
	idiag_cookie [2]uint32
}

// request structure
type inet_diag_req_v2 struct {
	sdiag_family uint8
	sdiag_protocol uint8
	sdiag_ext uint8
	pad uint8
	idiag_stats uint32
	id inet_diag_sockid
}
var order = nlenc.NativeEndian()

func (req inet_diag_req_v2) marshalBinary() ([]byte, error) {
	bytes := make([]byte,binary.Size(req))
	nlenc.PutUint8(bytes[0:1],req.sdiag_family)
	nlenc.PutUint8(bytes[1:2],req.sdiag_protocol)
	nlenc.PutUint8(bytes[2:3],req.sdiag_ext)
	nlenc.PutUint8(bytes[3:4],req.pad)
	nlenc.PutUint32(bytes[4:8],req.idiag_stats)
	//id 的写入:查找指定的socket inode 号
	nlenc.PutUint16(bytes[8:10],unint16LE2BE(req.id.idiag_sport))
	// 除了定义大小段可以使用binary的执行字节序 进行读写
	//binary.BigEndian.PutUint16(bytes[8:10],req.id.idiag_sport)
	//binary.BigEndian.Uint16(bytes[8:10])
	nlenc.PutUint16(bytes[10:12],unint16LE2BE(req.id.idiag_dport))
	nlenc.PutUint32(bytes[12:16],unint32LE2BE(req.id.idiag_src[0]))
	nlenc.PutUint32(bytes[28:32],unint32LE2BE(req.id.idiag_dst[0]))
	return bytes,nil
}

// resp struct
type inet_diag_msg struct {
	idiag_family uint8
	idiag_state uint8
	idiag_timer uint8
	idiag_retrans uint8
	id inet_diag_sockid
	idiag_expires uint32
	idiag_rqueue uint32
	idiag_wqueue uint32
	idiag_uid uint32
	idiag_inode uint32
}

func unmarshresp(data []byte) inet_diag_msg {
	resp := inet_diag_msg{}
	resp.idiag_family = nlenc.Uint8(data[0:1])
	resp.idiag_state = nlenc.Uint8(data[1:2])
	resp.idiag_timer = nlenc.Uint8(data[2:3])
	resp.idiag_retrans = nlenc.Uint8(data[3:4])

	resp.id.idiag_sport = nlenc.Uint16(data[4:6])
	resp.id.idiag_dport = nlenc.Uint16(data[6:8])
	resp.id.idiag_src[0] = nlenc.Uint32(data[8:12])
	resp.id.idiag_dst[0] = nlenc.Uint32(data[24:28])
	resp.id.idiag_if = nlenc.Uint32(data[40:44])
	resp.id.idiag_cookie[0] = nlenc.Uint32(data[44:48])
	resp.id.idiag_cookie[1] = nlenc.Uint32(data[48:52])

	resp.idiag_expires = nlenc.Uint32(data[52:56])
	resp.idiag_rqueue = nlenc.Uint32(data[56:60])
	resp.idiag_wqueue = nlenc.Uint32(data[60:64])
	resp.idiag_uid = nlenc.Uint32(data[64:68])
	resp.idiag_inode = nlenc.Uint32(data[68:72])
	return resp
}

// tcp socket state
type socket_stat uint32

const (
	TCP_ESTABLISHED = iota + 1
	TCP_SYN_SENT
	TCP_SYN_RECV
	TCP_FIN_WAIT1
	TCP_FIN_WAIT2
	TCP_TIME_WAIT
	TCP_CLOSE
	TCP_CLOSE_WAIT
	TCP_LAST_ACK
	TCP_LISTEN
	TCP_CLOSING
	TCPF_ALL = 0xFFF
)

const (
	INET_DIAG_NONE = iota
	INET_DIAG_MEMINFO
	INET_DIAG_INFO
	INET_DIAG_VEGASINFO
	INET_DIAG_CONG
	INET_DIAG_TOS
	INET_DIAG_TCLASS
	INET_DIAG_SKMEMINFO
	INET_DIAG_SHUTDOWN

	/*
	 * Next extenstions cannot be requested in struct inet_diag_req_v2:
	 * its field idiag_ext has only 8 bits.
	 */

	INET_DIAG_DCTCPINFO	/* request as INET_DIAG_VEGASINFO */
	INET_DIAG_PROTOCOL	/* response attribute only */
	INET_DIAG_SKV6ONLY
	INET_DIAG_LOCALS
	INET_DIAG_PEERS
	INET_DIAG_PAD
	INET_DIAG_MARK	/* only with CAP_NET_ADMIN */
	INET_DIAG_BBRINFO	/* request as INET_DIAG_VEGASINFO */
	INET_DIAG_CLASS_ID	/* request as INET_DIAG_TCLASS */
	INET_DIAG_MD5SIG
	INET_DIAG_ULP_INFO
	__INET_DIAG_MAX
)

func unint16LE2BE(s uint16) uint16 {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:],s)
	d := binary.BigEndian.Uint16(buf[:])
	return d
}

func unint32LE2BE(s uint32) uint32 {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:],s)
	d := binary.BigEndian.Uint32(buf[:])
	return d
}

