// Copied from pkg/qemu
package ctchecker

import (
	"encoding/json"
	"fmt"
	"net"
)

type QMProxy struct {
	MonPort int
	mon     net.Conn
	monEnc  *json.Encoder
	monDec  *json.Decoder
}
type qmpVersion struct {
	Package string
	QEMU    struct {
		Major int
		Micro int
		Minor int
	}
}

type qmpBanner struct {
	QMP struct {
		Version qmpVersion
	}
}

type qmpCommand struct {
	Execute   string      `json:"execute"`
	Arguments interface{} `json:"arguments,omitempty"`
}

type hmpCommand struct {
	Command string `json:"command-line"`
}

type qmpResponse struct {
	Error struct {
		Class string
		Desc  string
	}
	Return interface{}
}

func (inst *QMProxy) qmpConnCheck() error {
	if inst.mon != nil {
		return nil
	}

	addr := fmt.Sprintf("127.0.0.1:%v", inst.MonPort)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}

	monDec := json.NewDecoder(conn)
	monEnc := json.NewEncoder(conn)

	var banner qmpBanner
	if err := monDec.Decode(&banner); err != nil {
		return err
	}

	inst.monEnc = monEnc
	inst.monDec = monDec
	if _, err := inst.doQmp(&qmpCommand{Execute: "qmp_capabilities"}); err != nil {
		inst.monEnc = nil
		inst.monDec = nil
		return err
	}
	inst.mon = conn

	return nil
}

func (inst *QMProxy) qmpRecv() (*qmpResponse, error) {
	qmp := new(qmpResponse)
	err := inst.monDec.Decode(qmp)

	return qmp, err
}

func (inst *QMProxy) doQmp(cmd *qmpCommand) (*qmpResponse, error) {
	if err := inst.monEnc.Encode(cmd); err != nil {
		return nil, err
	}
	return inst.qmpRecv()
}

func (inst *QMProxy) qmp(cmd *qmpCommand) (interface{}, error) {
	if err := inst.qmpConnCheck(); err != nil {
		return nil, err
	}
	resp, err := inst.doQmp(cmd)
	if err != nil {
		return resp.Return, err
	}
	if resp.Error.Desc != "" {
		return resp.Return, fmt.Errorf("error %v", resp.Error)
	}
	if resp.Return == nil {
		return nil, fmt.Errorf(`no "return" nor "error" in [%v]`, resp)
	}
	return resp.Return, nil
}

func (inst *QMProxy) hmp(cmd string) (string, error) {
	req := &qmpCommand{
		Execute: "human-monitor-command",
		Arguments: &hmpCommand{
			Command: cmd,
		},
	}
	resp, err := inst.qmp(req)
	if err != nil {
		return "", err
	}
	return resp.(string), nil
}
