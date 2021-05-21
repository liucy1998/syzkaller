package ctchecker

// TODO: redesign file structures

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/prog"
)

type Shm struct {
	Path string
	Size int
}

type Fifo struct {
	Path string
}

type ESProxy struct {
	CmdMem         []byte
	In             *os.File
	Out            *os.File
	Err            *os.File
	status         *os.File
	statusChanDict map[int32]chan int32
}

// command
const runExecutor = 23
const killExecutor = 98

type ESExecReqHead struct {
	ArgvNum int
	EnvpNum int
	ShmSize int
}

type ESExecReq struct {
	Head ESExecReqHead
	Path string
	Argv []string
	Envp []string
}

type ESKillReq struct {
	Pid int
}

type ESStatus struct {
	Pid    int32
	Status int32
}

func addPrefix(index int, name string) string {
	prefix := "./" + strconv.FormatInt(int64(index), 10) + "-"
	return prefix + name
}
func GetESFifoIn(index int) Fifo {
	return Fifo{Path: addPrefix(index, "es-fifo-in")}
}
func GetESFifoOut(index int) Fifo {
	return Fifo{Path: addPrefix(index, "es-fifo-out")}
}
func GetESFifoErr(index int) Fifo {
	return Fifo{Path: addPrefix(index, "es-fifo-err")}
}
func GetESFifoStatus(index int) Fifo {
	return Fifo{Path: addPrefix(index, "es-fifo-status")}
}
func GetExecFifoIn(index int) Fifo {
	return Fifo{Path: addPrefix(index, "fifo-in")}
}
func GetExecFifoOut(index int) Fifo {
	return Fifo{Path: addPrefix(index, "fifo-out")}
}
func GetExecFifoErr(index int) Fifo {
	return Fifo{Path: addPrefix(index, "fifo-err")}
}
func GetESShmCmd(index int) Shm {
	return Shm{Path: addPrefix(index, "es-shm-cmd"), Size: 4 << 20}
}
func GetExecShmProg(index int) Shm {
	return Shm{Path: addPrefix(index, "shm-prog"), Size: prog.ExecBufferSize}
}
func GetExecShmCov(index int) Shm {
	return Shm{Path: addPrefix(index, "shm-cov"), Size: 16 << 20} // keep sync with ipc.outputSize
}
func (fifo *Fifo) Open() (f *os.File, err error) {
	f, err = os.OpenFile(fifo.Path, os.O_RDWR, 0666)
	if err != nil {
		err = fmt.Errorf("failed to open shm file: %v", err)
		os.Remove(fifo.Path)
		return
	}
	return
}
func (shm *Shm) Open() (f *os.File, mem []byte, err error) {
	f, err = os.OpenFile(shm.Path, os.O_RDWR, 0666)
	if err != nil {
		err = fmt.Errorf("failed to open shm file: %v", err)
		os.Remove(shm.Path)
		return
	}
	mem, err = syscall.Mmap(int(f.Fd()), 0, shm.Size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		err = fmt.Errorf("failed to mmap shm file: %v", err)
		f.Close()
		os.Remove(f.Name())
		return
	}
	return
}
func GetFifosShms(index int) ([]Fifo, []Shm) {

	fifos := []Fifo{
		GetESFifoIn(index),
		GetESFifoOut(index),
		GetESFifoErr(index),
		GetESFifoStatus(index),
		GetExecFifoIn(index),
		GetExecFifoOut(index),
		GetExecFifoErr(index),
	}

	shms := []Shm{
		GetESShmCmd(index),
		GetExecShmProg(index),
		GetExecShmCov(index),
	}

	return fifos, shms
}

func SetupFifosShms(index int) ([]Fifo, []Shm) {
	fifos, shms := GetFifosShms(index)

	for _, f := range fifos {
		os.Remove(f.Path)
		syscall.Mkfifo(f.Path, 0666)
	}

	for _, s := range shms {
		os.Remove(s.Path)
		os.Create(s.Path)
		os.Truncate(s.Path, int64(s.Size))
	}

	return fifos, shms
}

func MakeESProxy(index int) (esp *ESProxy, err error) {
	esp = &ESProxy{}
	var memfile *os.File
	cmdshm := GetESShmCmd(index)
	infifo := GetESFifoIn(index)
	outfifo := GetESFifoOut(index)
	errfifo := GetESFifoErr(index)
	statusfifo := GetESFifoStatus(index)
	memfile, esp.CmdMem, err = cmdshm.Open()
	if err != nil {
		return
	}
	memfile.Close()
	esp.In, err = infifo.Open()
	if err != nil {
		return
	}
	esp.Out, err = outfifo.Open()
	if err != nil {
		return
	}
	esp.Err, err = errfifo.Open()
	if err != nil {
		return
	}
	esp.status, err = statusfifo.Open()
	if err != nil {
		return
	}
	esp.statusChanDict = map[int32]chan int32{}
	go func() {
		for {
			var s ESStatus
			err = binary.Read(esp.status, binary.LittleEndian, &s)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Binary cannot read status: %v", err)
				break
			}
			esp.statusChanDict[s.Pid] <- s.Status
		}
	}()
	return
}

func (execReq *ESExecReq) Send(p *ESProxy) (ret int32) {
	// write shm
	st, ed := 0, len(execReq.Path)
	copy(p.CmdMem[st:ed], []byte(execReq.Path))
	p.CmdMem[ed] = 0

	for _, a := range execReq.Argv {
		st, ed = ed+1, ed+1+len(a)
		copy(p.CmdMem[st:ed], []byte(a))
		p.CmdMem[ed] = 0
	}

	for _, e := range execReq.Envp {
		st, ed = ed+1, ed+1+len(e)
		copy(p.CmdMem[st:ed], []byte(e))
		p.CmdMem[ed] = 0
	}

	// send req
	reqBytes := make([]byte, 16)
	binary.LittleEndian.PutUint32(reqBytes[0:], uint32(runExecutor))
	binary.LittleEndian.PutUint32(reqBytes[4:], uint32(execReq.Head.ArgvNum))
	binary.LittleEndian.PutUint32(reqBytes[8:], uint32(execReq.Head.EnvpNum))
	binary.LittleEndian.PutUint32(reqBytes[12:], uint32(ed))
	p.In.Write(reqBytes)

	// wait response
	retBytes := make([]byte, 4)
	p.Out.Read(retBytes)
	ret = int32(binary.LittleEndian.Uint32(retBytes))

	return
}

func (r *ESExecReq) Print() {

	fmt.Fprintf(os.Stderr, "––––––––––Execute Request––––––––\n")
	fmt.Fprintf(os.Stderr, "Argv num: %v\n", r.Head.ArgvNum)
	fmt.Fprintf(os.Stderr, "Envp num: %v\n", r.Head.EnvpNum)
	fmt.Fprintf(os.Stderr, "Path: %v\n", r.Path)
	fmt.Fprintf(os.Stderr, "Argv: %v\n", r.Argv)
	fmt.Fprintf(os.Stderr, "Envp: %v\n", r.Envp)
}

func Start(p *ESProxy, bin string, args []string, extraEnv []string) (pid int32, status chan int32) {
	execreq := &ESExecReq{
		Head: ESExecReqHead{
			ArgvNum: len(args),
			EnvpNum: len(extraEnv),
			ShmSize: 0, // ignore
		},
		Path: bin,
		Argv: args,
		Envp: extraEnv,
	}
	execreq.Print()
	pid = execreq.Send(p)
	status = make(chan int32, 4)
	p.statusChanDict[pid] = status
	return
}

func (killReq *ESKillReq) Send(p *ESProxy) (ret int) {
	// send req
	reqBytes := make([]byte, 8)
	binary.LittleEndian.PutUint32(reqBytes[0:], uint32(killExecutor))
	binary.LittleEndian.PutUint32(reqBytes[4:], uint32(killReq.Pid))
	p.In.Write(reqBytes)

	// wait response
	retBytes := make([]byte, 4)
	p.Out.Read(retBytes)
	ret = int(binary.LittleEndian.Uint32(retBytes))

	return
}

func Kill(p *ESProxy, ospid int) (ret int) {
	req := ESKillReq{Pid: ospid}
	return req.Send(p)
}

func enableFeature(f *host.Feature) {
	f.Enabled = true
	f.Reason = "enabled"
}

func Check() *host.Features {
	// TODO: do we need more features?
	// TODO: fix this ugly hard-coded features later...
	const unsupported = "support is not implemented in syzkaller"
	res := &host.Features{
		host.FeatureCoverage:         {Name: "code coverage", Reason: unsupported},
		host.FeatureComparisons:      {Name: "comparison tracing", Reason: unsupported},
		host.FeatureExtraCoverage:    {Name: "extra coverage", Reason: unsupported},
		host.FeatureSandboxSetuid:    {Name: "setuid sandbox", Reason: unsupported},
		host.FeatureSandboxNamespace: {Name: "namespace sandbox", Reason: unsupported},
		host.FeatureSandboxAndroid:   {Name: "Android sandbox", Reason: unsupported},
		host.FeatureFault:            {Name: "fault injection", Reason: unsupported},
		host.FeatureLeak:             {Name: "leak checking", Reason: unsupported},
		host.FeatureNetInjection:     {Name: "net packet injection", Reason: unsupported},
		host.FeatureNetDevices:       {Name: "net device setup", Reason: unsupported},
		host.FeatureKCSAN:            {Name: "concurrency sanitizer", Reason: unsupported},
		host.FeatureDevlinkPCI:       {Name: "devlink PCI setup", Reason: unsupported},
		host.FeatureUSBEmulation:     {Name: "USB emulation", Reason: unsupported},
		host.FeatureVhciInjection:    {Name: "hci packet injection", Reason: unsupported},
		host.FeatureWifiEmulation:    {Name: "wifi device emulation", Reason: unsupported},
		host.Feature802154Emulation:  {Name: "802.15.4 emulation", Reason: unsupported},
	}
	enableFeature(&res[host.FeatureCoverage])
	enableFeature(&res[host.FeatureSandboxNamespace])
	enableFeature(&res[host.FeatureSandboxSetuid])
	enableFeature(&res[host.FeatureNetInjection])
	enableFeature(&res[host.FeatureNetDevices])
	return res
}

func (p *QMProxy) SaveSnapshot() {
	res, err := p.hmp("savevm img")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Save Snapshot: response: %v\n", res)
		fmt.Fprintf(os.Stderr, "Save Snapshot: fail!\n")
	}
	res, err = p.hmp("cont")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cont: response: %v\n", res)
		fmt.Fprintf(os.Stderr, "Cont: fail!, error: %v\n", err)
	}
}

func (p *QMProxy) LoadSnapshot() {
	res, err := p.hmp("loadvm img")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Reload Snapshot: response: %v\n", res)
		fmt.Fprintf(os.Stderr, "Reload Snapshot: fail!\n")
	}
	res, err = p.hmp("cont")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cont: response: %v\n", res)
		fmt.Fprintf(os.Stderr, "Cont: fail!, error: %v\n", err)
	}
}
