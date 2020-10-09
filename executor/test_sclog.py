
import glob, subprocess

def cmp_log_trace(log, trace):
    sc_log_lines = [l_log.split(':', 1)[1].rsplit('=', 1)[0].strip() for l_log in log.strip().split('\n')]
    cnt_log = len(sc_log_lines)
    cnt_all = int(log.strip().rsplit('\n', 1)[-1].split(':', 1)[0]) + 1
    for i, sc_log in enumerate(sc_log_lines):
        if not trace.find("\n"+sc_log):
            return False, sc_log_lines[:i], sc_log , cnt_all, cnt_log
    return True, sc_log_lines, None, cnt_all, cnt_log

def strcat_file(pattern):
    res = ""
    for f_name in glob.glob(pattern):
        with open(f_name) as f:
            res += f.read() + "\n"
    return res

def get_test_log(prog_idx, prog_total, prog_name, suc, suc_sclogs, fail_sclog, trace, cnt_all, cnt_log):
    log = "--------------- PROG(" + str(prog_idx) + "/" + str(prog_total) + "): " + prog_name + " ---------------\n"
    log += "SYSCALL TESTED(THIS PROG): " + " ALL = " + str(cnt_all) + ", LOG = " + str(cnt_log) + "\n"
    log += "RESULT: "
    if suc:
        log += "SUCCESS!\n"
        if len(suc_sclogs) > 0:
            log += "[PASSED] "
            log += "\n[PASSED] ".join(suc_sclogs) + "\n"
    else:
        log += "FAIL!\n"
        if len(suc_sclogs) > 0:
            log += "[PASSED] "
            log += "\n[PASSED] ".join(suc_sclogs) + "\n"
        log += "[FAILED] " + fail_sclog
        log += "\n######################### Strace Log #########################\n"
        log += trace
    return log


test_log_name = "./test_log"
strace_log_name = "./log/trace"
prog_pattern = "../attacker/raw/*"


cmd_base = "strace -s 1000 -v -ff -o" + strace_log_name + " ./syz-execprog -executor=./syz-executor -collide=false -repeat=1 -procs=1 -cover=0 "
sclog_name = "/tmp/trace.0"
strace_log_name_pattern = strace_log_name + '*'

subprocess.run("mkdir -p " + strace_log_name.rsplit('/', 1)[0], shell=True)
cnt_allsc = 0 
cnt_logsc = 0 
cnt_numprog = 0
empty_l = []
with open(test_log_name, mode="w") as test_log_f:
    prog_list = glob.glob(prog_pattern)
    cnt_numprog = len(prog_list)
    for i, prog_name in enumerate(prog_list):
        print(prog_name)
        # clean up
        subprocess.run("rm "  + sclog_name, shell=True)
        subprocess.run("rm "  + strace_log_name_pattern, shell=True)
        # run cmd
        cmd = cmd_base + prog_name
        subprocess.run(cmd, shell=True)
        # cross checking system call log w/ strace log 
        with open(sclog_name) as log_f:
            log = log_f.read()
            if len(log) == 0:
                print("System call log is empty! Continue!")
                empty_l.append(prog_name)
                continue
            trace = strcat_file(strace_log_name_pattern)
            suc, suc_sclogs, fail_sclog, cnt_all_prog, cnt_log_prog = cmp_log_trace(log, trace)
            cnt_allsc += cnt_all_prog
            cnt_logsc += cnt_log_prog
            # test log
            test_log = get_test_log(i, cnt_numprog, prog_name, suc, suc_sclogs, fail_sclog, trace, cnt_all_prog, cnt_log_prog)
            print("\nSYSCALL TESTED: ALL =", cnt_allsc, ", LOG =", cnt_logsc)
            print(test_log)
            test_log_f.write(test_log)
    test_log_f.write("\nSYSCALL TESTED: ALL = " + str(cnt_allsc) + ", LOG = " + str(cnt_logsc) + "\n")
    test_log_f.write("\nEMPTY SYSCALL LOG:\n" + "\n".join(empty_l))