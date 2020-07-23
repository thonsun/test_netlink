package main

import (
	"bytes"
	"encoding/binary"
	"github.com/mdlayher/netlink"
	"log"
	"os"
	"syscall"
)

func main() {
	conf := netlink.Config{
		Groups:  CN_IDX_PROC, //需要加入多播组1
	}
	c, err := netlink.Dial(syscall.NETLINK_CONNECTOR,&conf)

	if err != nil {
		log.Fatalf("create netlink_connector socket error:%v",err)
	}
	defer c.Close()

	// 注册监听内核进程事件信息
	cn_id := cnID{
		Idx: CN_IDX_PROC,
		Val: CN_VAL_PROC,
	}
	cn_msg := cnMsg{
		ID:    cn_id,
		Len:   4,
		Flags: 0,
	}
	data := cn_msg.marshal2Bytes(PROC_CN_MCAST_LISTEN)

	req := netlink.Message{
		Header: netlink.Header{
			Type:     syscall.NLMSG_DONE,
			PID:      uint32(os.Getpid()),
		},
		Data:   data,
	}

	_ , err = c.Send(req)
	if err != nil {
		log.Printf("send msg error:%v",err)
	}

	for {
		msgs, err := c.Receive()
		if err != nil {
			log.Printf("recieve msg error:%v",err)
		}
		count := 0
		for _, msg := range msgs{
			buf := bytes.NewBuffer(msg.Data)
			m := &cnMsg{}
			hdr := &procEventHeader{}

			err := binary.Read(buf, binary.LittleEndian, m)
			if err != nil {
				log.Printf("parse cnmsg error:%v",err)
			}
			err = binary.Read(buf, binary.LittleEndian, hdr)
			if err != nil {
				log.Printf("parse proc event error:%v",err)
			}
			switch hdr.What {
			case PROC_EVENT_EXEC:
				event := &execProcEvent{}
				binary.Read(buf,binary.LittleEndian,event)
				count += 1
				log.Printf("exec pid:%v tgid:%v\n count:%d",event.ProcessPid,event.ProcessTgid,count)
			//case PROC_EVENT_FORK:
			//	event := &forkProcEvent{}
			//	binary.Read(buf,binary.LittleEndian,event)
			//	log.Printf("fork ppid:%v pid:%v\n",event.ParentPid,event.ChildPid)
			//case PROC_EVENT_EXIT:
			//	event := &exitProcEvent{}
			//	binary.Read(buf,binary.LittleEndian,&event)
			//	log.Printf("exit pid:%v code:%v\n",event.ProcessPid,event.ExitCode)
			//case PROC_EVENT_COMM:
			//	event := &commProcEvent{}
			//	binary.Read(buf,binary.LittleEndian,event)
			//	log.Printf("comm pid:%v comm:%v",event.ProcessPid,string(event.Comm[:]))
			}
		}
	}

}


/*
struct cnID {
	__u32 Idx;
	__u32 Val;
};

struct cnMsg {
	struct cnID ID;

	__u32 Seq;
	__u32 Ack;

	__u16 Len;		//Length of the following data
	__u16 Flags;
	__u8 data[0];
};
 */

type cnID struct {
	Idx uint32
	Val uint32
}

type cnMsg struct {
	ID    cnID
	Seq   uint32
	Ack   uint32
	Len   uint16
	Flags uint16
}

func (msg *cnMsg) marshal2Bytes(op uint32) []byte {
	buf := make([]byte,binary.Size(msg)+binary.Size(op))
	binary.LittleEndian.PutUint32(buf[0:4],msg.ID.Idx)
	binary.LittleEndian.PutUint32(buf[4:8],msg.ID.Val)
	binary.LittleEndian.PutUint32(buf[8:12],msg.Seq)
	binary.LittleEndian.PutUint32(buf[12:16],msg.Ack)
	binary.LittleEndian.PutUint16(buf[16:18],msg.Len)
	binary.LittleEndian.PutUint16(buf[18:20],msg.Flags)
	binary.LittleEndian.PutUint32(buf[20:24],op)
	return buf
}

const (
	//ID 标识
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

// linux/cn_proc.h:struc comm_proc_event.comm
type commProcEvent struct {
	ProcessPid uint32
	ProcessTgid uint32
	Comm [16]byte
}

// standard netlink header + connector header + data
type netlinkProcMessage struct {
	Header syscall.NlMsghdr
	Data   cnMsg
}