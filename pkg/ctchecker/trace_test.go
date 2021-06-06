package ctchecker

import (
	"testing"
)

func TestParse(t *testing.T) {
	tests := []string{
		`a(1, "axx\"\'", 0xdeadbeef123, {a=1, b=c}) = b {0}`,
		`socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM) = 3 {0}`,
		`fstat(3, {st_dev=makedev(0, 0x5), st_ino=9203, st_mode=S_IFCHR|0644, st_nlink=1, st_uid=0, st_gid=0, st_blksize=4096, st_blocks=0, st_rdev=makedev(0xa, 0xeb), st_atime=1606104069 /* 2020-11-23T04:01:09.667400719+0000 */, st_atime_nsec=667400719, st_mtime=1606104069 /* 2020-11-23T04:01:09.667400719+0000 */, st_mtime_nsec=667400719, st_ctime=1606104069 /* 2020-11-23T04:01:09.667400719+0000 */, st_ctime_nsec=667400719}) = 0 {0}`,
		`connect(3, {sa_family=AF_INET6, sin6_port=htons(0), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = 0 {0}`,
		`sendmmsg(3, [{msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(20004), sin_addr=inet_addr("0.0.0.0")}, msg_namelen=16, msg_iov=NULL, msg_iovlen=0, msg_controllen=0, msg_flags=0}, msg_len=0}, {msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(20001), sin_addr=inet_addr("224.0.0.1")}, msg_namelen=16, msg_iov=NULL, msg_iovlen=0, msg_control=[{cmsg_len=20, cmsg_level=SOL_IP, cmsg_type=IP_RETOPTS, cmsg_data=[0x86, 0x06, 0x00, 0x00]}], msg_controllen=20, msg_flags=0}}], 2, 0) = 1 {0}`,
		`ioctl(4, BTRFS_IOC_FILE_EXTENT_SAME or FIDEDUPERANGE, {src_offset=0, src_length=0, dest_count=484, info=[{dest_fd=-1, dest_offset=0}, {dest_fd=-1, dest_offset=0}]} => {info=[{bytes_deduped=0, status=0}, {bytes_deduped=0, status=0}]}) = -1 {0}`,
		`ioctl(-1, SNDCTL_TMR_STOP or TCSETSW, {c_iflags=0, c_oflags=0, c_cflags=0, c_lflags=0, c_line=0, c_cc[VMIN]=0, c_cc[VTIME]=0, c_cc="\x00\x00\x00\xea\xdf\x00\x00\x00\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"}) = -1 {0}`,
		`sendto(3, NULL, 0, 0, {sa_family=AF_INET6, sin6_port=htons(20002), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = 0 {0}`,
		`pselect6(64, [], NULL, [0 3], {tv_sec=0, tv_nsec=0}, NULL) = -1 {0}`,
	}

	for _, test := range tests {
		ts, err := Lex(test)
		t.Logf("Token Stream:\n%v", ts)
		if err != nil {
			t.Logf("%v", err)
			t.Errorf("Cannot lex %v", test)
		}
		n, err := Parse(ts)
		if err != nil {
			t.Logf("%v", err)
			t.Errorf("Cannot parse %v", test)
		}
		t.Logf("AST:\n%v\n", n.Serialze(false))
	}

}

func TestEqual(t *testing.T) {
	tests := []string{
		`f(a) = -1 {0}`,
		`f(a, b) = 0 {0}`,
		`f(a, y("a")) = -1 {0}`,
		`f(a, z("b")) = -1 {0}`,
		`f(a, d[A]) = -1 {0}`,
		`f(a, d[B]) = -1 {0}`,
		`f(a+2+3) = -1 {0}`,
		`f(a+1) = -1 {0}`,
	}
	for i := 0; i < len(tests); i += 2 {
		sa, err := Lex(tests[i])
		if err != nil {
			t.Logf("%v", err)
			t.Errorf("Cannot lex %v", tests[i])
		}
		sb, err := Lex(tests[i+1])
		if err != nil {
			t.Logf("%v", err)
			t.Errorf("Cannot lex %v", tests[i+1])
		}
		ta, err := Parse(sa)
		if err != nil {
			t.Logf("%v", err)
			t.Errorf("Cannot parse %v", tests[i])
		}
		tb, err := Parse(sb)
		if err != nil {
			t.Logf("%v", err)
			t.Errorf("Cannot parse %v", tests[i+1])
		}
		equal, reason := TraceNDEqual(ta, tb)
		t.Logf("equal=%v, reason=%v\n", equal, reason)
	}

}

func TestND(t *testing.T) {
	tests := []string{
		`f(a, c, d) = -1 {2}`,
		`f(a, b, d) = -1 {2}`,
		`f(a, 1+1, 12) = -1 {2}`,
		//
		`f(d) = -1 {2}`,
		`f(e, f) = -1 {2}`,
		`f(d) = 2 {2}`,
	}
	for i := 0; i < len(tests); i += 3 {
		sa, err := Lex(tests[i])
		if err != nil {
			t.Logf("%v", err)
			t.Errorf("Cannot lex %v", tests[i])
		}
		sb, err := Lex(tests[i+1])
		if err != nil {
			t.Logf("%v", err)
			t.Errorf("Cannot lex %v", tests[i+1])
		}
		sc, err := Lex(tests[i+2])
		if err != nil {
			t.Logf("%v", err)
			t.Errorf("Cannot lex %v", tests[i+2])
		}
		ta, err := Parse(sa)
		if err != nil {
			t.Logf("%v", err)
			t.Errorf("Cannot parse %v", tests[i])
		}
		tb, err := Parse(sb)
		if err != nil {
			t.Logf("%v", err)
			t.Errorf("Cannot parse %v", tests[i+1])
		}
		tc, err := Parse(sc)
		if err != nil {
			t.Logf("%v", err)
			t.Errorf("Cannot parse %v", tests[i+2])
		}
		TraceNDUpdate(ta, tb)
		equal, reason := TraceNDEqual(ta, tc)
		t.Logf("equal=%v, reason=%v\n", equal, reason)
	}

}
