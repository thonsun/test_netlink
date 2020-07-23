package main

import (
	"fmt"
	"github.com/elastic/go-libaudit"
	"github.com/elastic/go-libaudit/auparse"
	"github.com/elastic/go-libaudit/rule"
	"github.com/elastic/go-libaudit/rule/flags"
	"github.com/pkg/errors"
	"log"
	"os"
)

const debug bool = true

var logger *log.Logger

func init() {
	logger = log.New(os.Stdout,"[+]DEBUG[+]: ",log.Lshortfile | log.LstdFlags)
}

func infolog(format string,info...interface{}) {
	if debug {
		logger.Printf(format,info...)
	}
}

func main() {
	if err := read(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func read() error {
	if os.Geteuid() != 0 {
		return errors.New("you must be root to receive audit data")
	}

	var err error
	var client *libaudit.AuditClient
	client, err = libaudit.NewAuditClient(nil)
	if err != nil {
		return errors.Wrap(err, "failed to create audit client")
	}
	defer client.Close()

	infolog("%s","start to get rules")
	if rules,err := client.GetRules();err != nil{
		return errors.Wrap(err, "failed to get rules")
	}else {
		for _,rule := range rules{
			infolog("audit rules:%#v\n",rule)
		}
	}

	infolog("%s","start to set rules")
	r := "-a always,exit -F arch=b64 -S execve -k proc_create"
	addRule(r,client)
	//r = "-a always,exit -F arch=b64 -S bind -S listen -F success!=0 -k socket_create"
	//addRule(r,client)

	infolog("%s","start to get rules")
	if rules,err := client.GetRules();err != nil{
		return errors.Wrap(err, "failed to get rules")
	}else {
		for _,rule := range rules{
			infolog("audit rules:%#v\n",string(rule))
		}
	}

	status, err := client.GetStatus()
	if err != nil {
		return errors.Wrap(err, "failed to get audit status")
	}
	infolog("received audit status=%+v", status)

	// 开启Linux内核audit
	if status.Enabled == 0 {
		if err = client.SetEnabled(true, libaudit.WaitForReply); err != nil {
			return errors.Wrap(err, "failed to set enabled=true")
		}
	}

	infolog("sending message to kernel registering our PID (%v) as the audit daemon", os.Getpid())
	if err = client.SetPID(libaudit.NoWait); err != nil {
		return errors.Wrap(err, "failed to set audit PID")
	}

	return receive(client)
}

func receive(client *libaudit.AuditClient) error {
	for {
		// RawAuditMessage{
		//		Type: auparse.AuditMessageType(msgs[0].Header.Type),
		//		Data: msgs[0].Data,
		//	}
		//fmt.Printf("type=%#v msg=%#v\n", rawEvent.Type, string(rawEvent.Data))

		rawEvent, err := client.Receive(false)
		if err != nil {
			return errors.Wrap(err, "receive failed")
		}

		// Messages from 1300-2999 are valid audit messages.
		if rawEvent.Type < auparse.AUDIT_USER_AUTH ||
			rawEvent.Type > auparse.AUDIT_LAST_USER_MSG2 {
			continue
		}

		// 接收kernel audit的消息类型：systcall
		switch rawEvent.Type {
		case auparse.AUDIT_SYSCALL:
			fmt.Printf("type=%#v %#s\n","SYSCALL",string(rawEvent.Data))
		//case auparse.AUDIT_PATH:
		//	fmt.Printf("type=%#v %#s\n","PATH",string(rawEvent.Data))
		//case auparse.AUDIT_SOCKETCALL:
		//	fmt.Printf("type=%#v %#s\n","SYSTEM SOCKET",string(rawEvent.Data))
		//case auparse.AUDIT_CONFIG_CHANGE:
		//	fmt.Printf("type=%#v %#s\n","AUDIT_CONFIG_CHANGE",string(rawEvent.Data))
		//case auparse.AUDIT_CWD:
		//	fmt.Printf("type=%#v %#s\n","CWD",string(rawEvent.Data))
		//case auparse.AUDIT_EXECVE:
		//	fmt.Printf("type=%#v %#s\n","EXECUTE",string(rawEvent.Data))
		//case auparse.AUDIT_KERNEL_OTHER:
		//	fmt.Printf("type=%#v %#s\n","KERNEL_OTHER",string(rawEvent.Data))
		// other type
		//case auparse.AUDIT_FD_PAIR:
		//	fmt.Printf("type=%#v %#s\n","AUDIT_FD_PAIR",string(rawEvent.Data))
		//case auparse.AUDIT_NETFILTER_PKT:
		//	fmt.Printf("type=%#v %#s\n","AUDIT_NETFILTER_PKT",string(rawEvent.Data))
		default:
			//fmt.Printf("%s\n","other")
		}
	}
}

func addRule(ruleText string,client *libaudit.AuditClient) {
	ruleExec, _ := flags.Parse(ruleText)
	binaryRule, _ := rule.Build(ruleExec)
	infolog("%s","failed to build rule")
	if err := client.AddRule(binaryRule); err != nil {
		infolog("add audit rule err:%+v", err)
	}
}

