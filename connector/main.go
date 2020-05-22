package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/mdlayher/netlink"
	"log"
	"os"
	"syscall"
)

func main() {
	conf := netlink.Config{
		Groups:  CN_IDX_PROC,
	}
	c, err := netlink.Dial(syscall.NETLINK_CONNECTOR,nil)
	if err != nil {
		log.Fatalf("create netlink_connector socket error:%v",err)
	}
	defer c.Close()

	// 注册监听内核进程事件信息
	cn_id := cnID{
		idx: CN_IDX_PROC,
		val: CN_VAL_PROC,
	}
	cn_msg := cnMsg{
		id:    cn_id,
		len:   4,
		flags: 0,
	}
	data := cn_msg.marshal2Bytes(PROC_CN_MCAST_LISTEN)

	req := netlink.Message{
		Header: netlink.Header{
			Type:     syscall.NLMSG_DONE,
			PID:      uint32(os.Getpid()),
		},
		Data:   data,
	}

	resp, err := c.Send(req)
	if err != nil {
		log.Printf("send msg error:%v",err)
	}
	fmt.Print(resp.Header.Type,string(resp.Data))

	for {
		msgs, err := c.Receive()
		if err != nil {
			log.Printf("recieve msg error:%v",err)
		}
		for _, msg := range msgs{
			buf := bytes.NewBuffer(msg.Data)
			msg := &cnMsg{}
			hdr := &procEventHeader{}

			binary.Read(buf, binary.LittleEndian, msg)
			binary.Read(buf, binary.LittleEndian, hdr)
			switch hdr.What {
			case PROC_EVENT_EXEC:
				log.Println("exec")
			case PROC_EVENT_FORK:
				log.Println("fork")
			case PROC_EVENT_EXIT:
				log.Println("exit")
			}
		}
	}

}


/*
struct cnID {
	__u32 idx;
	__u32 val;
};

struct cnMsg {
	struct cnID id;

	__u32 seq;
	__u32 ack;

	__u16 len;		//Length of the following data
	__u16 flags;
	__u8 data[0];
};
 */

type cnID struct {
	idx uint32
	val uint32
}

type cnMsg struct {
	id    cnID
	seq   uint32
	ack   uint32
	len   uint16
	flags uint16
}

func (msg *cnMsg) marshal2Bytes(op uint32) []byte {
	buf := make([]byte,binary.Size(msg)+binary.Size(op))
	binary.LittleEndian.PutUint32(buf[0:4],msg.id.idx)
	binary.LittleEndian.PutUint32(buf[4:8],msg.id.val)
	binary.LittleEndian.PutUint32(buf[8:12],msg.seq)
	binary.LittleEndian.PutUint32(buf[12:16],msg.ack)
	binary.LittleEndian.PutUint16(buf[16:18],msg.len)
	binary.LittleEndian.PutUint16(buf[18:20],msg.flags)
	binary.LittleEndian.PutUint32(buf[20:24],op)
	return buf
}

const (
	//id 标识
	CN_IDX_PROC = 0x1
	CN_VAL_PROC	 = 0x1

	// connector 注册
	PROC_CN_MCAST_LISTEN = 1
	PROC_CN_MCAST_IGNORE = 2

	//proc event type：常用三个 fork,exec,exit
	PROC_EVENT_NONE = 0x00000000
	PROC_EVENT_FORK = 0x00000001
	PROC_EVENT_EXEC = 0x00000002
	PROC_EVENT_UID  = 0x00000004
	PROC_EVENT_GID  = 0x00000040
	PROC_EVENT_SID  = 0x00000080
	PROC_EVENT_PTRACE = 0x00000100
	PROC_EVENT_COMM = 0x00000200
	/* "next" should be 0x00000400 */
	/* "last" is the last process event: exit,
	 * while "next to last" is coredumping event */
	PROC_EVENT_COREDUMP = 0x40000000
	PROC_EVENT_EXIT = 0x80000000
)

// * parent process ID  =  parent->tgid
// * parent thread  ID  =  parent->pid
// * child  process ID  =  child->tgid
// * child  thread  ID  =  child->pid
// linux/cn_proc.h: struct proc_event.{what,cpu,timestamp_ns} + eventstruct 是connector返回的事件
type procEventHeader struct {
	What      uint32
	Cpu       uint32
	Timestamp uint64
}

// linux/cn_proc.h: struct proc_event.fork
type forkProcEvent struct {
	ParentPid  uint32
	ParentTgid uint32
	ChildPid   uint32
	ChildTgid  uint32
}

// linux/cn_proc.h: struct proc_event.exec
type execProcEvent struct {
	ProcessPid  uint32
	ProcessTgid uint32
}

// linux/cn_proc.h: struct proc_event.exit
type exitProcEvent struct {
	ProcessPid  uint32
	ProcessTgid uint32
	ExitCode    uint32
	ExitSignal  uint32
}

// standard netlink header + connector header + data
type netlinkProcMessage struct {
	Header syscall.NlMsghdr
	Data   cnMsg
}