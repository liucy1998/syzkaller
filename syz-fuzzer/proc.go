// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/ctchecker"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

// Proc represents a single fuzzing process (executor).
type Proc struct {
	fuzzer            *Fuzzer
	pid               int
	env               *ipc.Env
	aEnv              *ipc.Env
	dEnv              *ipc.Env
	rnd               *rand.Rand
	execOpts          *ipc.ExecOpts
	execOptsCover     *ipc.ExecOpts
	execOptsComps     *ipc.ExecOpts
	execOptsNoCollide *ipc.ExecOpts
}

func newProc(fuzzer *Fuzzer, pid int) (*Proc, error) {
	var env *ipc.Env
	var aEnv, dEnv *ipc.Env
	var err error
	if fuzzer.cc {
		aEnv, err = ipc.MakeEnvCC(fuzzer.config, fuzzer.index, true)
		if err != nil {
			return nil, err
		}
		dEnv, err = ipc.MakeEnvCC(fuzzer.config, fuzzer.index, false)
		if err != nil {
			return nil, err
		}
		log.Logf(1, "Make image now!!")
		err = ipc.MakeImageCC(fuzzer.sshkey, fuzzer.sshport, fuzzer.sshfwport, fuzzer.sshuser, fuzzer.sshdir, fuzzer.index, aEnv, dEnv, &fuzzer.qmProxy)
		if err != nil {
			return nil, err
		}
	} else {
		env, err = ipc.MakeEnv(fuzzer.config, pid)
		if err != nil {
			return nil, err
		}
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12))
	execOptsNoCollide := *fuzzer.execOpts
	execOptsNoCollide.Flags &= ^ipc.FlagCollide
	execOptsCover := execOptsNoCollide
	execOptsCover.Flags |= ipc.FlagCollectCover
	execOptsComps := execOptsNoCollide
	execOptsComps.Flags |= ipc.FlagCollectComps
	proc := &Proc{
		fuzzer:            fuzzer,
		pid:               pid,
		env:               env,
		rnd:               rnd,
		execOpts:          fuzzer.execOpts,
		execOptsCover:     &execOptsCover,
		execOptsComps:     &execOptsComps,
		execOptsNoCollide: &execOptsNoCollide,
		aEnv:              aEnv,
		dEnv:              dEnv,
	}
	return proc, nil
}

func (proc *Proc) loop() {
	generatePeriod := 100
	if proc.fuzzer.config.Flags&ipc.FlagSignal == 0 {
		// If we don't have real coverage signal, generate programs more frequently
		// because fallback signal is weak.
		generatePeriod = 2
	}
	for i := 0; ; i++ {
		item := proc.fuzzer.workQueue.dequeue()
		if item != nil {
			switch item := item.(type) {
			case *WorkTriage:
				proc.triageInput(item)
			case *WorkCandidate:
				proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
			case *WorkSmash:
				proc.smashInput(item)
			default:
				log.Fatalf("unknown work type: %#v", item)
			}
			continue
		}

		ct := proc.fuzzer.choiceTable
		fuzzerSnapshot := proc.fuzzer.snapshot()
		if len(fuzzerSnapshot.corpus) == 0 || i%generatePeriod == 0 {
			// Generate a new prog.
			p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
			log.Logf(1, "#%v: generated", proc.pid)
			proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)
		} else {
			// Mutate an existing prog.
			p := fuzzerSnapshot.chooseProgram(proc.rnd).Clone()
			p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
			log.Logf(1, "#%v: mutated", proc.pid)
			proc.execute(proc.execOpts, p, ProgNormal, StatFuzz)
		}
	}
}

func (proc *Proc) triageInput(item *WorkTriage) {
	log.Logf(1, "#%v: triaging type=%x", proc.pid, item.flags)

	prio := signalPrio(item.p, &item.info, item.call)
	inputSignal := signal.FromRaw(item.info.Signal, prio)
	newSignal := proc.fuzzer.corpusSignalDiff(inputSignal)
	if newSignal.Empty() {
		return
	}
	callName := ".extra"
	logCallName := "extra"
	if item.call != -1 {
		callName = item.p.Calls[item.call].Meta.Name
		logCallName = fmt.Sprintf("call #%v %v", item.call, callName)
	}
	log.Logf(3, "triaging input for %v (new signal=%v)", logCallName, newSignal.Len())
	var inputCover cover.Cover
	const (
		signalRuns       = 3
		minimizeAttempts = 3
	)
	// Compute input coverage and non-flaky signal for minimization.
	notexecuted := 0
	for i := 0; i < signalRuns; i++ {
		info := proc.executeRaw(proc.execOptsCover, item.p, StatTriage)
		if !reexecutionSuccess(info, &item.info, item.call) {
			// The call was not executed or failed.
			notexecuted++
			if notexecuted > signalRuns/2+1 {
				return // if happens too often, give up
			}
			continue
		}
		thisSignal, thisCover := getSignalAndCover(item.p, info, item.call)
		newSignal = newSignal.Intersection(thisSignal)
		// Without !minimized check manager starts losing some considerable amount
		// of coverage after each restart. Mechanics of this are not completely clear.
		if newSignal.Empty() && item.flags&ProgMinimized == 0 {
			return
		}
		inputCover.Merge(thisCover)
	}
	if item.flags&ProgMinimized == 0 {
		item.p, item.call = prog.Minimize(item.p, item.call, false,
			func(p1 *prog.Prog, call1 int) bool {
				for i := 0; i < minimizeAttempts; i++ {
					info := proc.execute(proc.execOptsNoCollide, p1, ProgNormal, StatMinimize)
					if !reexecutionSuccess(info, &item.info, call1) {
						// The call was not executed or failed.
						continue
					}
					thisSignal, _ := getSignalAndCover(p1, info, call1)
					if newSignal.Intersection(thisSignal).Len() == newSignal.Len() {
						return true
					}
				}
				return false
			})
	}

	data := item.p.Serialize()
	sig := hash.Hash(data)

	log.Logf(2, "added new input for %v to corpus:\n%s", logCallName, data)
	proc.fuzzer.sendInputToManager(rpctype.RPCInput{
		Call:   callName,
		Prog:   data,
		Signal: inputSignal.Serialize(),
		Cover:  inputCover.Serialize(),
	})

	proc.fuzzer.addInputToCorpus(item.p, inputSignal, sig)

	if item.flags&ProgSmashed == 0 {
		proc.fuzzer.workQueue.enqueue(&WorkSmash{item.p, item.call})
	}
}

func reexecutionSuccess(info *ipc.ProgInfo, oldInfo *ipc.CallInfo, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldInfo.Errno == 0 && info.Calls[call].Errno != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *ipc.ProgInfo, call int) (signal.Signal, []uint32) {
	inf := &info.Extra
	if call != -1 {
		inf = &info.Calls[call]
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call)), inf.Cover
}

func (proc *Proc) smashInput(item *WorkSmash) {
	if proc.fuzzer.faultInjectionEnabled && item.call != -1 {
		proc.failCall(item.p, item.call)
	}
	if proc.fuzzer.comparisonTracingEnabled && item.call != -1 {
		proc.executeHintSeed(item.p, item.call)
	}
	fuzzerSnapshot := proc.fuzzer.snapshot()
	for i := 0; i < 100; i++ {
		p := item.p.Clone()
		p.Mutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, fuzzerSnapshot.corpus)
		log.Logf(1, "#%v: smash mutated", proc.pid)
		proc.execute(proc.execOpts, p, ProgNormal, StatSmash)
	}
}

func (proc *Proc) failCall(p *prog.Prog, call int) {
	for nth := 0; nth < 100; nth++ {
		log.Logf(1, "#%v: injecting fault into call %v/%v", proc.pid, call, nth)
		opts := *proc.execOpts
		opts.Flags |= ipc.FlagInjectFault
		opts.FaultCall = call
		opts.FaultNth = nth
		info := proc.executeRaw(&opts, p, StatSmash)
		if info != nil && len(info.Calls) > call && info.Calls[call].Flags&ipc.CallFaultInjected == 0 {
			break
		}
	}
}

func (proc *Proc) executeHintSeed(p *prog.Prog, call int) {
	log.Logf(1, "#%v: collecting comparisons", proc.pid)
	// First execute the original program to dump comparisons from KCOV.
	info := proc.execute(proc.execOptsComps, p, ProgNormal, StatSeed)
	if info == nil {
		return
	}

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(call, info.Calls[call].Comps, func(p *prog.Prog) {
		log.Logf(1, "#%v: executing comparison hint", proc.pid)
		proc.execute(proc.execOpts, p, ProgNormal, StatHint)
	})
}

func (proc *Proc) execute(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat) *ipc.ProgInfo {
	info := proc.executeRaw(execOpts, p, stat)
	if info == nil {
		return nil
	}
	calls, extra := proc.fuzzer.checkNewSignal(p, info)
	for _, callIndex := range calls {
		proc.enqueueCallTriage(p, flags, callIndex, info.Calls[callIndex])
	}
	if extra {
		proc.enqueueCallTriage(p, flags, -1, info.Extra)
	}
	return info
}

func (proc *Proc) enqueueCallTriage(p *prog.Prog, flags ProgTypes, callIndex int, info ipc.CallInfo) {
	// info.Signal points to the output shmem region, detach it before queueing.
	info.Signal = append([]uint32{}, info.Signal...)
	// None of the caller use Cover, so just nil it instead of detaching.
	// Note: triage input uses executeRaw to get coverage.
	info.Cover = nil
	proc.fuzzer.workQueue.enqueue(&WorkTriage{
		p:     p.Clone(),
		call:  callIndex,
		info:  info,
		flags: flags,
	})
}

func (proc *Proc) executeRaw(opts *ipc.ExecOpts, p *prog.Prog, stat Stat) *ipc.ProgInfo {
	proc.executeCC(proc.execOpts, p, p, StatCandidate)
	if opts.Flags&ipc.FlagDedupCover == 0 {
		log.Fatalf("dedup cover is not enabled")
	}
	for _, call := range p.Calls {
		if !proc.fuzzer.choiceTable.Enabled(call.Meta.ID) {
			fmt.Printf("executing disabled syscall %v\n", call.Meta.Name)
			panic("disabled syscall")
		}
	}

	// Limit concurrency window and do leak checking once in a while.
	ticket := proc.fuzzer.gate.Enter()
	defer proc.fuzzer.gate.Leave(ticket)

	proc.logProgram(opts, p)
	for try := 0; ; try++ {
		atomic.AddUint64(&proc.fuzzer.stats[stat], 1)
		var output []byte
		var info *ipc.ProgInfo
		var hanged bool
		var err error
		if proc.fuzzer.cc {
			emptyProg := &prog.Prog{
				Target: p.Target,
			}
			proc.fuzzer.qmProxy.LoadSnapshot()
			// attacker run an empty program
			proc.aEnv.ExecCC(opts, emptyProg, proc.fuzzer.index)
			// detector run the actual program
			_, output, info, hanged, err = proc.dEnv.ExecCC(opts, p, proc.fuzzer.index)
		} else {
			output, info, hanged, err = proc.env.Exec(opts, p)
		}
		if err != nil {
			if err == prog.ErrExecBufferTooSmall {
				// It's bad if we systematically fail to serialize programs,
				// but so far we don't have a better handling than ignoring this.
				// This error is observed a lot on the seeded syz_mount_image calls.
				return nil
			}
			if try > 10 {
				log.Fatalf("executor %v failed %v times:\n%v", proc.pid, try, err)
			}
			log.Logf(4, "fuzzer detected executor failure='%v', retrying #%d", err, try+1)
			debug.FreeOSMemory()
			time.Sleep(time.Second)
			continue
		}
		log.Logf(2, "result hanged=%v: %s", hanged, output)
		return info
	}
}

func (proc *Proc) executeCC(opts *ipc.ExecOpts, pa, pd *prog.Prog, stat Stat) {
	if opts.Flags&ipc.FlagDedupCover == 0 {
		log.Fatalf("dedup cover is not enabled")
	}
	for _, call := range pd.Calls {
		if !proc.fuzzer.choiceTable.Enabled(call.Meta.ID) {
			fmt.Printf("executing disabled syscall %v\n", call.Meta.Name)
			panic("disabled syscall")
		}
	}
	for _, call := range pa.Calls {
		if !proc.fuzzer.choiceTable.Enabled(call.Meta.ID) {
			fmt.Printf("executing disabled syscall %v\n", call.Meta.Name)
			panic("disabled syscall")
		}
	}

	// Disable collide mode
	newOpts := &ipc.ExecOpts{
		Flags:     opts.Flags & ^ipc.FlagCollide,
		FaultCall: opts.FaultCall,
		FaultNth:  opts.FaultNth,
	}

	// Limit concurrency window and do leak checking once in a while.
	ticket := proc.fuzzer.gate.Enter()
	defer proc.fuzzer.gate.Leave(ticket)

	atomic.AddUint64(&proc.fuzzer.stats[stat], 1)
	var output []byte
	var hanged bool
	var err error
	var dTracemem, aTracemem [][]byte
	var dCandTrace, dTestTrace *ctchecker.ProgTrace
	var traceEqual, sigEqual bool
	var reason string
	// var dInfo, dCandInfo, dTestInfo *ipc.ProgInfo
	// send program & trace to manager
	var atrace *ctchecker.ProgTrace

	var dCandRawSig, dTestRawSig []uint32
	var pInfo *ipc.ProgInfo
	var newIFSig []ctchecker.IFSignal

	emptyProg := &prog.Prog{
		Target: pd.Target,
	}
	proc.fuzzer.qmProxy.LoadSnapshot()
	// attacker run an empty program
	proc.aEnv.ExecCC(newOpts, emptyProg, proc.fuzzer.index)
	// detector run the actual program
	dTracemem, output, pInfo, hanged, err = proc.dEnv.ExecCC(newOpts, pd, proc.fuzzer.index)
	if err != nil {
		log.Logf(4, "fuzzer detected detector failure='%v', quit", err)
		return
	}
	dCandTrace, err = ctchecker.ParseTrace(dTracemem)
	if err != nil {
		log.Logf(4, "fuzzer can not parse detector trace failure='%v', quit", err)
		log.Logf(4, "trace 0:\n%v", string(dTracemem[0][:ctchecker.BufTrailingZero(dTracemem[0])]))
		return
	}
	for _, call := range pInfo.Calls {
		dCandRawSig = append(dCandRawSig, call.Signal...)
	}
	dCandRawSig = append(dCandRawSig, pInfo.Extra.Signal...)

	proc.fuzzer.qmProxy.LoadSnapshot()
	aTracemem, output, _, hanged, err = proc.aEnv.ExecCC(newOpts, pa, proc.fuzzer.index)
	if err != nil {
		log.Logf(4, "fuzzer detected attacker failure='%v', quit", err)
		return
	}
	log.Logf(2, "attacker result hanged=%v: %s", hanged, output)
	dTracemem, output, pInfo, hanged, err = proc.dEnv.ExecCC(newOpts, pd, proc.fuzzer.index)
	if err != nil {
		log.Logf(4, "fuzzer detected detector failure='%v', quit", err)
		return
	}
	log.Logf(2, "detector result hanged=%v: %s", hanged, output)
	dTestTrace, err = ctchecker.ParseTrace(dTracemem)
	if err != nil {
		log.Logf(4, "%v", err)
		return
	}
	for _, call := range pInfo.Calls {
		dTestRawSig = append(dTestRawSig, call.Signal...)
	}
	dTestRawSig = append(dTestRawSig, pInfo.Extra.Signal...)

	traceEqual, reason = ctchecker.ProgTraceNDEqual(dCandTrace, dTestTrace)
	if !traceEqual {
		// We must parse attacker trace now,
		// or the buffer will be cleared in next non-determinism reduction executions
		atrace, err = ctchecker.ParseTrace(aTracemem)
		if err != nil {
			log.Logf(4, "fuzzer can not compare attacker trace failure='%v' when sending report, quit", err)
			return
		}
	}

	ifSig := ctchecker.GenIFSigal(dCandRawSig, dTestRawSig)
	proc.fuzzer.ifSignalMu.RLock()
	sigEqual = !proc.fuzzer.detIFSignalSet.CheckNew(ifSig)
	proc.fuzzer.ifSignalMu.RUnlock()

	if traceEqual && sigEqual {
		log.Logf(4, "Equal! Early quit!")
		return
	}
	if !sigEqual {
		log.Logf(0, "Number of ifsig: %v", len(ifSig))
		log.Logf(0, "IFSIG: %v", ifSig)
	}

	log.Logf(0, "CC execution: stage A-D non-determinisim")
	// handling A-D non-determinism
	var dTestTraceNDOk, dTestSigNDOk bool
	for {
		var trace *ctchecker.ProgTrace
		proc.fuzzer.qmProxy.LoadSnapshot()
		_, output, _, hanged, err = proc.aEnv.ExecCC(newOpts, pa, proc.fuzzer.index)
		if err != nil {
			log.Logf(4, "fuzzer detected attacker failure='%v', quit", err)
			return
		}
		log.Logf(2, "attacker result hanged=%v: %s", hanged, output)
		dTracemem, output, pInfo, hanged, err = proc.dEnv.ExecCC(newOpts, pd, proc.fuzzer.index)
		if err != nil {
			log.Logf(4, "fuzzer detected detector failure='%v', quit", err)
			return
		}
		log.Logf(2, "detector result hanged=%v: %s", hanged, output)
		if !traceEqual && !dTestTraceNDOk {
			trace, err = ctchecker.ParseTrace(dTracemem)
			if err != nil {
				log.Logf(4, "%v", err)
				return
			}
			nomatch, updated := ctchecker.ProgTraceNDUpdate(dTestTrace, trace)
			if nomatch {
				log.Logf(4, "trace does not match")
				return
			}
			if !updated {
				dTestTraceNDOk = true
			}
		}
		if !sigEqual && !dTestSigNDOk {
			var tmpSig []uint32
			for _, call := range pInfo.Calls {
				tmpSig = append(tmpSig, call.Signal...)
			}
			tmpSig = append(tmpSig, pInfo.Extra.Signal...)
			tmpSig = ctchecker.RawSigIntersection(dTestRawSig, tmpSig)
			if len(tmpSig) == len(dTestRawSig) {
				// Successfully filter non-deterministic signals
				dTestSigNDOk = true
			}
			dTestRawSig = tmpSig
		}
		if (traceEqual != dTestTraceNDOk) && (sigEqual != dTestSigNDOk) {
			break
		}
	}

	log.Logf(0, "CC execution: stage D non-determinisim")
	// handling D non-determinism
	var dCandTraceNDOk, dCandSigNDOk bool
	for {
		var trace *ctchecker.ProgTrace
		proc.fuzzer.qmProxy.LoadSnapshot()
		// attacker run an empty program
		proc.aEnv.ExecCC(newOpts, emptyProg, proc.fuzzer.index)
		// detector run the actual program
		dTracemem, output, _, hanged, err = proc.dEnv.ExecCC(newOpts, pd, proc.fuzzer.index)
		if err != nil {
			log.Logf(4, "fuzzer detected detector failure='%v' when dealing non-determinism, quit", err)
			return
		}
		if !traceEqual && !dCandTraceNDOk {
			trace, err = ctchecker.ParseTrace(dTracemem)
			if err != nil {
				log.Logf(4, "%v", err)
				return
			}
			nomatch, updated := ctchecker.ProgTraceNDUpdate(dCandTrace, trace)
			if nomatch {
				log.Logf(4, "trace does not match")
				return
			}
			if !updated {
				dCandTraceNDOk = true
			}
		}
		if !sigEqual && !dCandSigNDOk {
			var tmpSig []uint32
			for _, call := range pInfo.Calls {
				tmpSig = append(tmpSig, call.Signal...)
			}
			tmpSig = append(tmpSig, pInfo.Extra.Signal...)
			tmpSig = ctchecker.RawSigIntersection(dCandRawSig, tmpSig)
			if len(tmpSig) == len(dCandRawSig) {
				// Successfully filter non-deterministic signals
				dCandSigNDOk = true
			}
			dCandRawSig = tmpSig
		}
		if (traceEqual != dCandTraceNDOk) && (sigEqual != dCandSigNDOk) {
			break
		}
	}

	if !traceEqual {
		traceEqual, reason = ctchecker.ProgTraceNDEqual(dCandTrace, dTestTrace)
	}
	if !sigEqual {

		log.Logf(0, "After minimization:")
		newIFSig = ctchecker.GenIFSigal(dCandRawSig, dTestRawSig)
		log.Logf(0, "Number of ifsig: %v", len(ifSig))
		log.Logf(0, "IFSIG: %v", ifSig)
		proc.fuzzer.ifSignalMu.RLock()
		sigEqual = !proc.fuzzer.detIFSignalSet.CheckNew(newIFSig)
		proc.fuzzer.ifSignalMu.RUnlock()
	}

	if traceEqual && sigEqual {
		log.Logf(4, "False positive!")
		return
	}

	proc.fuzzer.ifSignalMu.Lock()
	proc.fuzzer.ifSigCnt = proc.fuzzer.detIFSignalSet.Merge(newIFSig, proc.fuzzer.ifSigCnt)
	proc.fuzzer.ifSignalMu.Unlock()

	if !sigEqual {
		r := &rpctype.IFSigReportArgs{
			Name: proc.fuzzer.name,
			IFSigReport: rpctype.IFSigReport{
				Sig: newIFSig,
			},
		}
		if err := proc.fuzzer.manager.Call("Manager.NewIFSigReport", r, nil); err != nil {
			log.Fatalf("Manager.NewIFSigReport call failed: %v", err)
		}
	}

	if !traceEqual {

		dett := dCandTrace.DeterminSerialze()
		log.Logf(4, "DETERMINISM trace:\n%v\n", string(dett))

		r := &rpctype.CCReportArgs{
			Name: proc.fuzzer.name,
			CCReport: rpctype.CCReport{
				AProg:         pa.Serialize(),
				DProg:         pd.Serialize(),
				ATrace:        atrace.RawSerialze(),
				DTraceCandRaw: dCandTrace.RawSerialze(),
				DTraceCandDet: dCandTrace.DeterminSerialze(),
				DTraceTestRaw: dTestTrace.RawSerialze(),
				Reason:        reason,
				EnvFlags:      uint64(proc.fuzzer.config.Flags),
				ExecFlags:     uint64(newOpts.Flags),
				FaultCall:     newOpts.FaultCall,
				FaultNth:      newOpts.FaultNth,
			},
		}
		if err := proc.fuzzer.manager.Call("Manager.NewCCReport", r, nil); err != nil {
			log.Fatalf("Manager.NewCCReport call failed: %v", err)
		}
	}
	return

}

func (proc *Proc) logProgram(opts *ipc.ExecOpts, p *prog.Prog) {
	if proc.fuzzer.outputType == OutputNone {
		return
	}

	data := p.Serialize()
	strOpts := ""
	if opts.Flags&ipc.FlagInjectFault != 0 {
		strOpts = fmt.Sprintf(" (fault-call:%v fault-nth:%v)", opts.FaultCall, opts.FaultNth)
	}

	// The following output helps to understand what program crashed kernel.
	// It must not be intermixed.
	switch proc.fuzzer.outputType {
	case OutputStdout:
		now := time.Now()
		proc.fuzzer.logMu.Lock()
		fmt.Printf("%02v:%02v:%02v executing program %v%v:\n%s\n",
			now.Hour(), now.Minute(), now.Second(),
			proc.pid, strOpts, data)
		proc.fuzzer.logMu.Unlock()
	case OutputDmesg:
		fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
		if err == nil {
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "syzkaller: executing program %v%v:\n%s\n",
				proc.pid, strOpts, data)
			syscall.Write(fd, buf.Bytes())
			syscall.Close(fd)
		}
	case OutputFile:
		f, err := os.Create(fmt.Sprintf("%v-%v.prog", proc.fuzzer.name, proc.pid))
		if err == nil {
			if strOpts != "" {
				fmt.Fprintf(f, "#%v\n", strOpts)
			}
			f.Write(data)
			f.Close()
		}
	default:
		log.Fatalf("unknown output type: %v", proc.fuzzer.outputType)
	}
}
