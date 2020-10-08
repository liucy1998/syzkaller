
import glob, subprocess

def cmp_log_trace(log, trace):
    sc_log_lines = [l_log.split(':')[1].rsplit('=', 1)[0].strip() for l_log in log.strip().split('\n')]
    for i, sc_log in enumerate(sc_log_lines):
        if not trace.find("\n"+sc_log):
            return False, sc_log_lines[:i], sc_log 
    return True, sc_log_lines, None

def strcat_file(pattern):
    res = ""
    for f_name in glob.glob(pattern):
        with open(f_name) as f:
            res += f.read() + "\n"
    return res

def get_test_log(suc, suc_sclogs, fail_sclog, trace):
    log = ""
    if suc:
        log += "SUCCESS!\n"
        log += " [PASSED]\n".join(suc_sclogs) + " [PASSED]\n"
    else:
        log += "FAIL!\n"
        log += " [PASSED]\n".join(suc_sclogs) + " [PASSED]\n"
        log += fail_sclog + " [FAILED]\n"
        log += "\n######################### Strace Log #########################\n"
        log += trace
    return log


cmd = "sudo strace -s 1000 -v -ff -o ./log/trace ./syz-execprog -executor=./syz-executor -collide=false -repeat=1 -procs=1 -cover=0 ../attacker//raw/001*"
trace_name = r"./log/trace*"
log_name = r"/tmp/trace.0"
fail_log_name = "./test_fail_log"

# subprocess.run(cmd, shell=True)
with open(log_name) as log_f:
    log = log_f.read()
    trace = strcat_file(trace_name)
    suc, suc_sclogs, fail_sclog = cmp_log_trace(log, trace)
    test_log = get_test_log(suc, suc_sclogs, fail_sclog, trace)
    print(test_log)
    
