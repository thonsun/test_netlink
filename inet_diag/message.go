package main

import (
	"encoding/binary"
	"github.com/mdlayher/netlink/nlenc"
)

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

func (req inet_diag_req_v2) marshalBinary() ([]byte, error) {
	bytes := make([]byte,binary.Size(req))
	nlenc.PutUint8(bytes[0:1],req.sdiag_family)
	nlenc.PutUint8(bytes[1:2],req.sdiag_protocol)
	nlenc.PutUint8(bytes[2:3],req.sdiag_ext)
	nlenc.PutUint8(bytes[3:4],req.pad)
	nlenc.PutUint32(bytes[4:8],req.idiag_stats)
	//id 的写入
	nlenc.PutUint16(bytes[8:10],req.id.idiag_sport)
	nlenc.PutUint16(bytes[10:12],req.id.idiag_dport)
	nlenc.PutUint32(bytes[12:16],req.id.idiag_src[0])
	nlenc.PutUint32(bytes[28:32],req.id.idiag_dst[0])
	return bytes,nil
}

// tcp socket state
type socket_stat uint32

const (
	_ socket_stat = iota
	TCP_ESTABLISHED
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




